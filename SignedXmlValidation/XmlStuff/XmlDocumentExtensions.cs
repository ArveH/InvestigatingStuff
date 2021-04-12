using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using SignedXmlValidation.FromSaml.Helpers;

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

        public static void Sign2(this XmlElement xmlElement,
            X509Certificate2 cert,
            bool includeKeyInfo,
            string signingAlgorithm)
        {
            if (xmlElement == null)
            {
                throw new ArgumentNullException(nameof(xmlElement));
            }

            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var signedXml = new SignedXmlWithIdFix(xmlElement.OwnerDocument);

            // The transform XmlDsigExcC14NTransform and canonicalization method XmlDsigExcC14NTransformUrl is important for partially signed XML files
            // see: http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml.xmldsigexcc14ntransformurl(v=vs.110).aspx
            // The reference URI has to be set correctly to avoid assertion injections
            // For both, the ID/Reference and the Transform/Canonicalization see as well: 
            // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf section 5.4.2 and 5.4.3

            signedXml.SigningKey = cert.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = signingAlgorithm;

            // We need a document unique ID on the element to sign it -- make one up if it's missing
            string id = xmlElement.GetAttribute("ID");
            if (String.IsNullOrEmpty(id))
            {
                id = "_" + Guid.NewGuid().ToString("N");
                xmlElement.SetAttribute("ID", id);
            }
            var reference = new Reference
            {
                Uri = "#" + id,
                DigestMethod = GetCorrespondingDigestAlgorithm(signingAlgorithm)
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);
            signedXml.ComputeSignature();

            if (includeKeyInfo)
            {
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.KeyInfo = keyInfo;
            }

            xmlElement.InsertAfter(
                xmlElement.OwnerDocument.ImportNode(signedXml.GetXml(), true),
                xmlElement["Issuer", "urn:oasis:names:tc:SAML:2.0:assertion"]);
        }

        private static string[] GetKnownDigestAlgorithms()
        {
            if (EnvironmentHelpers.IsNetCore)
            {
                return new string[] {
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    "http://www.w3.org/2001/04/xmldsig-more#sha384",
                    "http://www.w3.org/2001/04/xmlenc#sha512"
                };
            }
            return typeof(SignedXml).GetFields()
                .Where(f => f.Name.StartsWith("XmlDsigSHA", StringComparison.Ordinal))
                .Select(f => (string)f.GetRawConstantValue())
                .OrderBy(f => f)
                .ToArray();
        }

        internal static readonly string[] DigestAlgorithms = GetKnownDigestAlgorithms();

        internal static string GetCorrespondingDigestAlgorithm(string signingAlgorithm)
        {
            var matchPattern = signingAlgorithm.Substring(signingAlgorithm.LastIndexOf('-') + 1);
            string match = DigestAlgorithms.FirstOrDefault(a => a.EndsWith(
                matchPattern,
                StringComparison.Ordinal));
            if (match == null)
            {
                throw new InvalidOperationException(
                    $"Unable to find a digest algorithm for the signing algorithm {signingAlgorithm}");
            }
            return match;
        }
    }
}