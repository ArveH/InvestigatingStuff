using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignedXmlValidation.XmlStuff
{
    public static class XmlDocumentExtensions
    {
        public static void Sign(this XmlDocument doc,
            X509Certificate2 cert, string elementId, string elementName = null)
        {
            if (doc == null)
            {
                throw new ArgumentNullException(nameof(doc));
            }

            var rsaKey = ((RSA)cert.PrivateKey);

            var signedXml = new SignedXml(doc) { SigningKey = rsaKey };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(cert);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            var reference = new Reference("#" + elementId);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();
            var signatureElement = signedXml.GetXml();

            var signatureParent = string.IsNullOrWhiteSpace(elementName)
                ? doc.DocumentElement
                : doc.GetElementsByTagName(elementName)[0];
            signatureParent?.AppendChild(doc.ImportNode(signatureElement, true));
        }
    }
}