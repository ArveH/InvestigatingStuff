using System.Xml;

namespace SignedXmlValidation.XmlStuff
{
    public class XmlCreator
    {
        public static XmlDocument CreateXml(string id,
            string assertionId,
            string inResponseTo,
            string host,
            string userEmail,
            string audienceRestriction,
            string returnUrl)
        {
            var doc = new XmlDocument();

            var samlResponse = new SamlResponse();
            var assertion = new Assertion();

            var responseNode = samlResponse.CreateXml(
                doc, id, Constants.XmlElementNames.Response, inResponseTo, host, returnUrl);
            var assertionNode = assertion.CreateXml(
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