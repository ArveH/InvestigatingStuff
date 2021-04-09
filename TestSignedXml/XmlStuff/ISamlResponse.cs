using System.Xml;

namespace TestSignedXml
{
    public interface ISamlResponse
    {
        XmlNode CreateXml(XmlDocument doc,
            string id,
            string elementName,
            string inResponseTo,
            string host,
            string returnUrl);
    }
}