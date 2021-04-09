using FluentAssertions;
using SignedXmlValidation;
using SignedXmlValidation.CertStuff;
using SignedXmlValidation.XmlStuff;
using System.Xml;
using Xunit;

namespace SignedXmlTester
{
    public class XmlTester
    {
        [Fact]
        public void TestXmlXCreator()
        {
            var doc = XmlCreator.CreateXml(
                Constants.Saml.AuthResponseId,
                "assertion-id_2021-04-09T055047.8132195Z",
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");
            doc.OuterXml.Should().StartWith("<samlp:Response");
        }

        [Fact]
        public void TestSigning()
        {
            var elementId = "assertion-id_2021-04-09T055047.8132195Z";
            var doc = XmlCreator.CreateXml(
                Constants.Saml.AuthResponseId,
                elementId,
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");
            // "saml:Assertion"
            var elementName = $"{Constants.XmlNSName.Saml}:{Constants.XmlElementNames.Assertion}";
            var x509 = CertCreator.GenerateX509Certificate();
            doc.Sign(x509, elementId, elementName);

            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("s", "http://www.w3.org/2000/09/xmldsig#");
            var node = doc.SelectSingleNode("//s:X509Data", nsMgr);
            node?.FirstChild?.Name.Should().Be("X509Certificate");
        }

    }
}
