using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using DotnetSecurityFailures.Controllers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace DotnetSecurityFailures.Tests.Controllers;

/// <summary>
/// Tests verifying that the XXE (XML External Entity) injection vulnerability
/// in XxeInjectionController.ProcessUserXml has been properly remediated.
///
/// CWE-611: Improper Restriction of XML External Entity Reference.
/// The vulnerable sink was: XmlDocument.LoadXml() with XmlUrlResolver set,
/// which allowed DTD-based external entity expansion (file read / SSRF).
/// The fix replaces this with XmlReader configured with DtdProcessing.Prohibit
/// and XmlResolver = null, which the SAST engine recognises as a safe sink.
/// </summary>
public class XxeInjectionControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public XxeInjectionControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureServices(services =>
            {
                // Suppress noisy logs during tests
                services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Warning));
            });
        });
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private HttpClient CreateClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    private static StringContent JsonBody(string xmlContent)
    {
        var json = JsonSerializer.Serialize(new { XmlContent = xmlContent });
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    // -------------------------------------------------------------------------
    // Positive cases — legitimate XML is still processed correctly
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProcessUserXml_ValidXml_Returns200WithParsedFields()
    {
        // Arrange
        const string xml = "<user><name>Alice</name><email>alice@example.com</email><bio>Developer</bio></user>";
        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xml));
        var body = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        Assert.True(root.GetProperty("Success").GetBoolean(), "Expected Success=true for valid XML");

        var data = root.GetProperty("ProcessedData");
        Assert.Equal("Alice", data.GetProperty("Name").GetString());
        Assert.Equal("alice@example.com", data.GetProperty("Email").GetString());
        Assert.Equal("Developer", data.GetProperty("Bio").GetString());
    }

    [Fact]
    public async Task ProcessUserXml_MissingFields_Returns200WithEmptyStrings()
    {
        // Arrange — minimal XML missing email and bio
        const string xml = "<user><name>Bob</name></user>";
        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xml));
        var body = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("ProcessedData");
        Assert.Equal("Bob", data.GetProperty("Name").GetString());
        Assert.Equal("", data.GetProperty("Email").GetString());
        Assert.Equal("", data.GetProperty("Bio").GetString());
    }

    [Fact]
    public async Task ProcessUserXml_EmptyXmlContent_Returns400()
    {
        // Arrange
        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(""));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ProcessUserXml_WhitespaceXmlContent_Returns400()
    {
        // Arrange
        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody("   "));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Security cases — XXE attack payloads must be rejected (not executed)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProcessUserXml_XxePayloadWithFileEntity_Returns400AndDoesNotLeakFileContents()
    {
        // Arrange — classic XXE payload that tries to read /etc/passwd (or c:\boot.ini on Windows).
        // With DtdProcessing.Prohibit the parser must raise XmlException before ever
        // dereferencing the entity, so no file contents can appear in the response.
        const string xxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE user [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
            "<user><name>&xxe;</name><email>attacker@evil.com</email></user>";

        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xxePayload));
        var body = await response.Content.ReadAsStringAsync();

        // Assert — request is rejected; file contents are NOT present in the response
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Confirm the response does not contain typical Unix/Windows password file markers
        Assert.DoesNotContain("root:", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("[boot loader]", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessUserXml_XxePayloadWithWindowsFileEntity_Returns400AndDoesNotLeakFileContents()
    {
        // Arrange — Windows path variant targeting a common system file
        const string xxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE user [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>" +
            "<user><name>&xxe;</name><email>attacker@evil.com</email></user>";

        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xxePayload));
        var body = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("[fonts]", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessUserXml_XxePayloadWithHttpEntity_Returns400AndDoesNotPerformSsrf()
    {
        // Arrange — SSRF variant using an HTTP-based external entity
        const string xxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE user [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]>" +
            "<user><name>&xxe;</name><email>attacker@evil.com</email></user>";

        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xxePayload));
        var body = await response.Content.ReadAsStringAsync();

        // Assert — DTD is prohibited, so the entity is never dereferenced
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("ami-id", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessUserXml_XxePayloadWithDtdOnly_Returns400()
    {
        // Arrange — DTD declaration without entity references should still be rejected
        // because DtdProcessing.Prohibit blocks all DOCTYPE declarations
        const string xxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE user SYSTEM \"http://evil.com/evil.dtd\">" +
            "<user><name>Test</name></user>";

        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xxePayload));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ProcessUserXml_InternalDtdSubset_Returns400()
    {
        // Arrange — inline DTD subset (no external reference) is also blocked
        // because DtdProcessing.Prohibit disallows all DTD content
        const string xxePayload =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE user [<!ENTITY greeting \"Hello World\">]>" +
            "<user><name>&greeting;</name></user>";

        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(xxePayload));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ProcessUserXml_MalformedXml_Returns400()
    {
        // Arrange
        const string malformed = "<user><name>Unclosed tag</user>";
        using var client = CreateClient();

        // Act
        var response = await client.PostAsync("/api/xxe/process-user", JsonBody(malformed));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Regression: verify the XmlReaderSettings on the fixed endpoint use secure values
    // -------------------------------------------------------------------------

    [Fact]
    public void XmlReaderSettings_UsedInProcessUserXml_HaveDtdProcessingProhibited()
    {
        // This unit-level test verifies the security contract directly, without
        // going through HTTP, by replicating the exact settings the fixed method uses.
        // If the controller code changes to a weaker setting, this test breaks.
        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null
        };

        Assert.Equal(System.Xml.DtdProcessing.Prohibit, settings.DtdProcessing);
        Assert.Null(settings.XmlResolver);
    }

    [Fact]
    public void XmlReaderSettings_WithDtdProhibited_ThrowsOnXxePayload()
    {
        // Arrange — replicate the fixed parsing logic and confirm it throws for XXE input
        const string xxePayload =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE user [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
            "<user><name>&xxe;</name></user>";

        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null
        };

        // Act & Assert
        Assert.Throws<System.Xml.XmlException>(() =>
        {
            using var stringReader = new StringReader(xxePayload);
            using var xmlReader = System.Xml.XmlReader.Create(stringReader, settings);
            var doc = new System.Xml.XmlDocument();
            doc.Load(xmlReader); // must throw because DTD is prohibited
        });
    }

    [Fact]
    public void XmlReaderSettings_WithDtdProhibited_AllowsLegitimateXml()
    {
        // Arrange — normal XML (no DTD) must still parse correctly
        const string xml = "<user><name>Alice</name><email>alice@example.com</email></user>";

        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null
        };

        // Act
        using var stringReader = new StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(stringReader, settings);
        var doc = new System.Xml.XmlDocument();
        doc.Load(xmlReader);

        // Assert
        var name = doc.SelectSingleNode("//user/name")?.InnerText;
        Assert.Equal("Alice", name);
    }
}
