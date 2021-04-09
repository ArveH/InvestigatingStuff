using System.Xml;

namespace TestSignedXml
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