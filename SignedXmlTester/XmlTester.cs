using FluentAssertions;
using SignedXmlValidation;
using SignedXmlValidation.XmlStuff;
using Xunit;

namespace SignedXmlTester
{
    public class XmlTester
    {
        [Fact]
        public void TestXmlXCreator()
        {
            var creator = new XmlCreator();
            var doc = creator.CreateXml(
                Constants.Saml.AuthResponseId,
                "assertion-id_2021-04-09T055047.8132195Z",
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");

            doc.OuterXml.Should().StartWith("<samlp:Response");

            // "saml:Assertion"
            var elementName = $"{Constants.XmlNSName.Saml}:{Constants.XmlElementNames.Assertion}";
        }
    }
}
