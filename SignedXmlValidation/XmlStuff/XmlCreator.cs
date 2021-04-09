using System.Xml;

namespace SignedXmlValidation.XmlStuff
{
    public class XmlCreator
    {
        private ISamlResponse _samlResponse;
        private IAssertion _assertion;

        public XmlCreator()
        {
            _samlResponse = new SamlResponse();
            _assertion = new Assertion();
        }

        public XmlDocument CreateXml(string id,
            string assertionId,
            string inResponseTo,
            string host,
            string userEmail,
            string audienceRestriction,
            string returnUrl)
        {
            var doc = new XmlDocument();

            var responseNode = _samlResponse.CreateXml(
                doc, id, Constants.XmlElementNames.Response, inResponseTo, host, returnUrl);
            var assertionNode = _assertion.CreateXml(
                doc,
                assertionId,
                Constants.Saml.AuthResponseId,
                host,
                userEmail,
                audienceRestriction,
                returnUrl);
            responseNode.AppendChild(assertionNode);

            doc.AppendChild(responseNode);
            return doc;
        }
    }
}