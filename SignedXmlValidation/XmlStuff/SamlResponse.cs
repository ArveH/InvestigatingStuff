using System;
using System.Xml;

namespace SignedXmlValidation.XmlStuff
{
    public class SamlResponse : ISamlResponse
    {
        public XmlNode CreateXml(XmlDocument doc,
            string id,
            string elementName,
            string inResponseTo,
            string host,
            string returnUrl)
        {
            var now = DateTime.Now;

            var responseNode = doc.CreateElement(
                Constants.XmlNSName.Samlp,
                elementName,
                Constants.XmlNS.Protocol);
            responseNode.AddAttr(doc, Constants.XmlAttrNames.Id, id);
            responseNode.AddAttr(doc, Constants.XmlAttrNames.InResponseTo, inResponseTo);
            responseNode.AddAttr(doc, Constants.XmlAttrNames.Version, Constants.XmlAttrValues.V2_0);
            responseNode.AddAttr(doc, Constants.XmlAttrNames.IssueInstant, now.ToString("O"));
            responseNode.AddAttr(doc, Constants.XmlAttrNames.Destination, returnUrl);

            var issuerNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Issuer,
                Constants.XmlNS.AssertionV2);
            issuerNode.InnerText = "https://" + host;
            responseNode.AppendChild(issuerNode);

            var statusNode = doc.CreateElement(
                Constants.XmlNSName.Samlp,
                Constants.XmlElementNames.Status,
                Constants.XmlNS.Protocol);
            responseNode.AppendChild(statusNode);

            var statusCodeNode = doc.CreateElement(
                Constants.XmlNSName.Samlp,
                Constants.XmlElementNames.StatusCode,
                Constants.XmlNS.Protocol);
            statusCodeNode.AddAttr(doc, Constants.XmlAttrNames.Value, Constants.XmlNS.Success);
            statusNode.AppendChild(statusCodeNode);

            return responseNode;
        }
    }
}