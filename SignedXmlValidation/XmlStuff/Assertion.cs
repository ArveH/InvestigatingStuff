using System;
using System.Xml;

namespace TestSignedXml
{
    public class Assertion : IAssertion
    {
        public XmlNode CreateXml(XmlDocument doc,
            string assertionId,
            string inResponseTo,
            string host,
            string userEmail,
            string audienceRestriction,
            string returnUrl)
        {
            var now = DateTime.Now;
            var sessionIndex = "not_sure_what_this_does";

            var assertionNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Assertion,
                Constants.XmlNS.AssertionV2);
            assertionNode.AddAttr(doc, Constants.XmlAttrNames.Version, Constants.XmlAttrValues.V2_0);
            assertionNode.AddAttr(doc, Constants.XmlAttrNames.Id, assertionId);
            assertionNode.AddAttr(doc, Constants.XmlAttrNames.IssueInstant, now.ToString("O"));

            var issuerNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Issuer,
                Constants.XmlNS.AssertionV2);
            issuerNode.InnerText = "https://" + host;
            assertionNode.AppendChild(issuerNode);
            assertionNode.AppendChild(CreateSubjectNode(doc, inResponseTo, userEmail, returnUrl, now));
            assertionNode.AppendChild(CreateConditionsNode(doc, audienceRestriction, now));
            assertionNode.AppendChild(CreateAuthnStatementNode(doc, sessionIndex, now));
            assertionNode.AppendChild(CreateAttributeStatementNode(doc, now));

            return assertionNode;
        }

        private static XmlElement CreateSubjectNode(XmlDocument doc,
            string inResponseTo,
            string userEmail,
            string returnUrl,
            DateTime now)
        {
            var subjectNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Subject,
                Constants.XmlNS.AssertionV2);
            var nameIdNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.NameID,
                Constants.XmlNS.AssertionV2);
            nameIdNode.AddAttr(doc, Constants.XmlAttrNames.Format, Constants.XmlNS.NameIdUnspecified);
            nameIdNode.InnerText = userEmail;
            subjectNode.AppendChild(nameIdNode);
            var subjectConfirmationNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.SubjectConfirmation,
                Constants.XmlNS.AssertionV2);
            subjectConfirmationNode.AddAttr(doc, Constants.XmlAttrNames.Method, Constants.XmlNS.Bearer);
            subjectNode.AppendChild(subjectConfirmationNode);
            var subjectConfirmationDataNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.SubjectConfirmationData,
                Constants.XmlNS.AssertionV2);
            subjectConfirmationDataNode.AddAttr(
                doc, Constants.XmlAttrNames.NotOnOrAfter, now.AddHours(1).ToString("O"));
            subjectConfirmationDataNode.AddAttr(
                doc, Constants.XmlAttrNames.Recipient, returnUrl);
            subjectConfirmationDataNode.AddAttr(
                doc, Constants.XmlAttrNames.InResponseTo, inResponseTo);
            subjectConfirmationNode.AppendChild(subjectConfirmationDataNode);
            return subjectNode;
        }

        private XmlNode CreateConditionsNode(XmlDocument doc, string audienceRestriction, in DateTime now)
        {
            var conditionsNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Conditions,
                Constants.XmlNS.AssertionV2);
            conditionsNode.AddAttr(
                doc, Constants.XmlAttrNames.NotBefore, now.ToString("O"));
            conditionsNode.AddAttr(
                doc, Constants.XmlAttrNames.NotOnOrAfter, now.AddHours(1).ToString("O"));

            var audienceRestrictionNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AudienceRestriction,
                Constants.XmlNS.AssertionV2);
            conditionsNode.AppendChild(audienceRestrictionNode);

            var audienceNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Audience,
                Constants.XmlNS.AssertionV2);
            audienceNode.InnerText = audienceRestriction;
            audienceRestrictionNode.AppendChild(audienceNode);

            return conditionsNode;
        }

        private XmlNode CreateAuthnStatementNode(XmlDocument doc, string sessionIndex, DateTime now)
        {
            var authnStatementNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AuthnStatement,
                Constants.XmlNS.AssertionV2);
            authnStatementNode.AddAttr(
                doc, Constants.XmlAttrNames.AuthnInstant, now.ToString("O"));
            authnStatementNode.AddAttr(
                doc, Constants.XmlAttrNames.SessionIndex, sessionIndex);

            var authnContextNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AuthnContext,
                Constants.XmlNS.AssertionV2);
            authnStatementNode.AppendChild(authnContextNode);

            var authnContextClassRefNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AuthnContextClassRef,
                Constants.XmlNS.AssertionV2);
            authnContextClassRefNode.InnerText = Constants.XmlNS.ClassesUnspecified;
            authnContextNode.AppendChild(authnContextClassRefNode);

            return authnStatementNode;
        }

        private XmlNode CreateAttributeStatementNode(XmlDocument doc, in DateTime now)
        {
            var attributeStatementNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AttributeStatement,
                Constants.XmlNS.AssertionV2);
            attributeStatementNode.AddNS(doc, Constants.XmlNSName.Xsd);
            attributeStatementNode.AddNS(doc, Constants.XmlNSName.Xsi);

            attributeStatementNode.AppendChild(
                CreateAttr(doc, Constants.Saml.ClaimName.Email, "someuser@email.com", Constants.ClaimType.String));
            attributeStatementNode.AppendChild(
                CreateAttr(doc, Constants.Saml.ClaimName.Upn, "someuser@email.com", Constants.ClaimType.String));
            attributeStatementNode.AppendChild(
                CreateAttr(doc, Constants.Saml.ClaimName.UserId, "user_id_" + "someuser@email.com", Constants.ClaimType.String));
            attributeStatementNode.AppendChild(
                CreateAttr(doc, Constants.Saml.ClaimName.Provider, "FakeIdp", Constants.ClaimType.String));
            attributeStatementNode.AppendChild(
                CreateAttr(doc, 
                    Constants.Saml.ClaimName.Name, 
                    "Some User",
                    Constants.ClaimType.String));

            return attributeStatementNode;
        }

        private XmlNode CreateAttr(XmlDocument doc, string name, string value, string type)
        {
            var attrNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.Attribute,
                Constants.XmlNS.AssertionV2);
            attrNode.AddAttr(
                doc, Constants.XmlAttrNames.Name, Constants.Saml.ClaimName.Name);
            attrNode.AddAttr(
                doc, Constants.XmlAttrNames.NameFormat, Constants.XmlNS.AttrNameFormatUri);

            var attrValueNode = doc.CreateElement(
                Constants.XmlNSName.Saml,
                Constants.XmlElementNames.AttributeValue,
                Constants.XmlNS.AssertionV2);
            attrValueNode.AddAttr(
                doc, 
                Constants.XmlNSName.Xsi,
                Constants.XmlAttrNames.Type, 
                "xsd:" + type);
            attrValueNode.InnerText = value;

            attrNode.AppendChild(attrValueNode);
            return attrNode;
        }
    }
}