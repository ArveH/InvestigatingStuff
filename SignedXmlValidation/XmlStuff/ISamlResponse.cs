using System.Xml;

namespace SignedXmlValidation.XmlStuff
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