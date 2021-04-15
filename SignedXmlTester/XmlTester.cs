using FluentAssertions;
using SignedXmlValidation;
using SignedXmlValidation.CertStuff;
using SignedXmlValidation.FromSaml.Helpers;
using SignedXmlValidation.XmlStuff;
using System;
using System.Collections;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Xunit;

namespace SignedXmlTester
{
    public class XmlTester
    {
        private readonly string minIncomingSignatureAlgorithm =
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        private readonly string elementId = "assertion-id_2021-04-09T055047.8132195Z";
        private readonly X509Certificate2 _certificate;

        public XmlTester()
        {
            _certificate = CertCreator.GenerateCACertificate("For Testing");
        }

        [Fact]
        public void TestXmlXCreator()
        {
            var doc = CreateXmlDoc();

            doc.OuterXml.Should().StartWith("<samlp:Response");
        }

        [Fact]
        public void TestSigning()
        {
            var doc = CreateXmlDoc();
            Sign(doc);

            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("s", "http://www.w3.org/2000/09/xmldsig#");
            var node = doc.SelectSingleNode("//s:X509Data", nsMgr);
            node?.FirstChild?.Name.Should().Be("X509Certificate");
        }

        [Fact]
        public void Verify_Using_IsSignedByAny()
        {
            var doc = CreateXmlDoc();
            Sign(doc);

            var isSigned = doc.DocumentElement.IsSignedByAny(
                _certificate,
                false,
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
            isSigned.Should().BeTrue();
        }

        [Fact]
        public void RabbitHoleTest()
        {
            var doc = CreateXmlDoc();
            Sign(doc);

            var xmlElement = doc.DocumentElement;
            var signedXml = new SignedXmlWithIdFix(xmlElement);

            var signatureElement = xmlElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            if (signatureElement == null)
            {
                throw new ArgumentNullException(nameof(signatureElement));
            }

            signedXml.LoadXml(signatureElement);
            XmlHelpers.ValidateReference(
                signedXml, xmlElement,
                XmlHelpers.GetCorrespondingDigestAlgorithm(minIncomingSignatureAlgorithm));

            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(BuildBagOfCerts(signedXml));
            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
            bool chainVerified = chain.Build(_certificate);

            XmlHelpers.VerifySignature(_certificate, signedXml, signatureElement, false);

        }

        private X509Certificate2Collection BuildBagOfCerts(
            SignedXmlWithIdFix signedXml)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            if (signedXml.KeyInfo != null)
            {
                foreach (KeyInfoClause clause in signedXml.KeyInfo)
                {
                    KeyInfoX509Data x509Data = clause as KeyInfoX509Data;
                    if (x509Data != null)
                        collection.AddRange(BuildBagOfCerts(
                            x509Data, CertUsageType.Verification));
                }
            }

            return collection;
        }

        internal enum CertUsageType
        {
            Verification = 0,
            Decryption = 1
        }

        public struct X509IssuerSerial
        {
            internal X509IssuerSerial(string issuerName, string serialNumber)
                : this()
            {
                Debug.Assert(!string.IsNullOrEmpty(issuerName));
                Debug.Assert(!string.IsNullOrEmpty(serialNumber));

                IssuerName = issuerName;
                SerialNumber = serialNumber;
            }

            public string IssuerName { get; set; }
            public string SerialNumber { get; set; }
        }

        internal static X509Certificate2Collection BuildBagOfCerts(KeyInfoX509Data keyInfoX509Data, CertUsageType certUsageType)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            ArrayList decryptionIssuerSerials = (certUsageType == CertUsageType.Decryption ? new ArrayList() : null);
            if (keyInfoX509Data.Certificates != null)
            {
                foreach (X509Certificate2 certificate in keyInfoX509Data.Certificates)
                {
                    switch (certUsageType)
                    {
                        case CertUsageType.Verification:
                            collection.Add(certificate);
                            break;
                    }
                }
            }

            if (keyInfoX509Data.SubjectNames == null && keyInfoX509Data.IssuerSerials == null &&
                keyInfoX509Data.SubjectKeyIds == null && decryptionIssuerSerials == null)
                return collection;

            // Open LocalMachine and CurrentUser "Other People"/"My" stores.

            X509Store[] stores = new X509Store[2];
            string storeName = (certUsageType == CertUsageType.Verification ? "AddressBook" : "My");
            stores[0] = new X509Store(storeName, StoreLocation.CurrentUser);
            stores[1] = new X509Store(storeName, StoreLocation.LocalMachine);

            for (int index = 0; index < stores.Length; index++)
            {
                if (stores[index] != null)
                {
                    X509Certificate2Collection filters = null;
                    // We don't care if we can't open the store.
                    try
                    {
                        stores[index].Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        filters = stores[index].Certificates;
                        stores[index].Close();
                        if (keyInfoX509Data.SubjectNames != null)
                        {
                            foreach (string subjectName in keyInfoX509Data.SubjectNames)
                            {
                                filters = filters.Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);
                            }
                        }
                        if (keyInfoX509Data.IssuerSerials != null)
                        {
                            foreach (X509IssuerSerial issuerSerial in keyInfoX509Data.IssuerSerials)
                            {
                                filters = filters.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
                                filters = filters.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
                            }
                        }
                        if (keyInfoX509Data.SubjectKeyIds != null)
                        {
                            foreach (byte[] ski in keyInfoX509Data.SubjectKeyIds)
                            {
                                string hex = HexConverter.ToString(ski);
                                filters = filters.Find(X509FindType.FindBySubjectKeyIdentifier, hex, false);
                            }
                        }
                        if (decryptionIssuerSerials != null)
                        {
                            foreach (X509IssuerSerial issuerSerial in decryptionIssuerSerials)
                            {
                                filters = filters.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
                                filters = filters.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
                            }
                        }
                    }
                    // Store doesn't exist, no read permissions, other system error
                    catch (CryptographicException) { }
                    // Opening LocalMachine stores (other than Root or CertificateAuthority) on Linux
                    catch (PlatformNotSupportedException) { }

                    if (filters != null)
                        collection.AddRange(filters);
                }
            }

            return collection;
        }

        private void Sign(XmlDocument doc)
        {
            doc.DocumentElement.Sign2(
                _certificate,
                true,
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        }

        private XmlDocument CreateXmlDoc()
        {
            var doc = XmlCreator.CreateXml(
                Constants.Saml.AuthResponseId,
                elementId,
                "id486364ad7bf040b0a3b6f35cc39c1ceb",
                "localhost:44388",
                "gal.gadot@unit4.com",
                "https://localhost:44300",
                "https://localhost:44300/identity/AuthServices/Acs");
            return doc;
        }
    }
}
