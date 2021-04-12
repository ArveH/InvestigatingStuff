using System.Security.Cryptography.Xml;
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
        private readonly string elementId = "assertion-id_2021-04-09T055047.8132195Z";

        [Fact]
        public void TestXmlXCreator()
        {
            var doc = CreateXmlDoc();

            doc.OuterXml.Should().StartWith("<samlp:Response");
        }

        [Fact]
        public void TestSigning()
        {
            var doc = CreateXmlDoc();
            Sign(doc);

            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("s", "http://www.w3.org/2000/09/xmldsig#");
            var node = doc.SelectSingleNode("//s:X509Data", nsMgr);
            node?.FirstChild?.Name.Should().Be("X509Certificate");
        }

        [Fact]
        public void TestVerify()
        {
            var doc = CreateXmlDoc();
            Sign(doc);
        }


        private void Sign(XmlDocument doc)
        {
            // "saml:Assertion"
            var elementName = $"{Constants.XmlNSName.Saml}:{Constants.XmlElementNames.Assertion}";
            var x509 = CertCreator.GenerateX509Certificate("For Testing");
            doc.Sign(x509, elementId, elementName);
        }

        private XmlDocument CreateXmlDoc()
        {
            var doc = XmlCreator.CreateXml(
                Constants.Saml.AuthResponseId,
                elementId,
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");
            return doc;
        }
    }
}
