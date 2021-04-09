using System.Xml;

namespace SignedXmlValidation.XmlStuff
{
    public interface IAssertion
    {
        XmlNode CreateXml(XmlDocument doc,
            string assertionId,
            string inResponseTo,
            string host,
            string userEmail,
            string audienceRestriction,
            string returnUrl);
    }
}