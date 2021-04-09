using System.Xml;

namespace TestSignedXml
{
    public static class XmlExtensions
    {
        public static void AddNS(this XmlNode node, XmlDocument doc, string prefix)
        {
            var nsName = $"xmlns:{prefix}";
            var attr = doc.CreateAttribute(nsName);
            attr.Value = ToNS(prefix);
            node.Attributes?.Append(attr);
        }

        public static void AddAttr(this XmlNode node, XmlDocument doc, string name, string val)
        {
            var attr = doc.CreateAttribute(name);
            attr.Value = val;
            node.Attributes?.Append(attr);
        }

        public static void AddAttr(this XmlNode node, XmlDocument doc, string prefix, string name, string val)
        {
            var attr = doc.CreateAttribute(prefix, name, ToNS(prefix));
            attr.Value = val;
            node.Attributes?.Append(attr);
        }

        public static string ToNS(string prefix)
        {
            return prefix switch
            {
                Constants.XmlNSName.Fed => Constants.XmlNS.Fed,
                Constants.XmlNSName.Wsa => Constants.XmlNS.Addressing,
                Constants.XmlNSName.Wsx => Constants.XmlNS.Mex,
                Constants.XmlNSName.Xsd => Constants.XmlNS.XmlSchema,
                Constants.XmlNSName.Xsi => Constants.XmlNS.XmlSchemaInstance,
                _ => ""
            };
        }
    }
}