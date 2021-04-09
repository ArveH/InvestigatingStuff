using System.Security.Cryptography.Xml;
using System.Xml;
using FluentAssertions;
using SignedXmlValidation;
using SignedXmlValidation.CertStuff;
using SignedXmlValidation.XmlStuff;
using Xunit;

namespace SignedXmlTester
{
    public class XmlTester
    {
        private XmlDocument _doc;

        public XmlTester()
        {
            _doc = XmlCreator.CreateXml(
                Constants.Saml.AuthResponseId,
                "assertion-id_2021-04-09T055047.8132195Z",
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");
        }

        [Fact]
        public void TestXmlXCreator()
        {
            _doc.OuterXml.Should().StartWith("<samlp:Response");

            // "saml:Assertion"
            var elementName = $"{Constants.XmlNSName.Saml}:{Constants.XmlElementNames.Assertion}";
        }

        [Fact]
        public void TestSigning()
        {
            // "saml:Assertion"
            var elementName = $"{Constants.XmlNSName.Saml}:{Constants.XmlElementNames.Assertion}";

            var x509 = CertCreator.GenerateX509Cert2();
            var signedXml = new SignedXml(_doc) {SigningKey = x509.PrivateKey};
        }

    }
}
