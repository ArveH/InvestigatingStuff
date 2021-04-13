using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignedXmlValidation.CertStuff
{
    public class CertCreator
    {
        private const string SignatureAlgorithm = "SHA256WithRSA";

        public static X509Certificate2 GenerateCACertificate(
            string subjectName, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(
                BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            certificateGenerator.SetSubjectAndIssuer(subjectName);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Generate KeyPair
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var keyPair = keyPairGenerator.GenerateKeyPair();

            // Generate Signature Factory
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                SignatureAlgorithm, keyPair.Private);

            // Set extensions
            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(true));
            var ski = new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    keyPair.Public));
            certificateGenerator.AddExtension(
                X509Extensions.SubjectKeyIdentifier, false, ski);

            // Add Public Key
            certificateGenerator.SetPublicKey(keyPair.Public);

            // Generating the BC Certificate
            var certificate = certificateGenerator.Generate(sigFact);

            // Add Private key (and convert to X509Certificate2)
            var x509 = GenerateX509WithPrivateKey(
                keyPair, certificate);

            return x509;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Interoperability", 
            "CA1416:Validate platform compatibility", 
            Justification = "It's only being used on Windows")]
        public static AsymmetricAlgorithm ToDotNetKey(
            RsaPrivateCrtKeyParameters privateKey)
        {
            var cspParams = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int) KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            var rsaProvider = new RSACryptoServiceProvider(cspParams);
            var parameters = new RSAParameters
            {
                Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                P = privateKey.P.ToByteArrayUnsigned(),
                Q = privateKey.Q.ToByteArrayUnsigned(),
                DP = privateKey.DP.ToByteArrayUnsigned(),
                DQ = privateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKey.QInv.ToByteArrayUnsigned(),
                D = privateKey.Exponent.ToByteArrayUnsigned(),
                Exponent = privateKey.PublicExponent.ToByteArrayUnsigned()
            };

            rsaProvider.ImportParameters(parameters);
            return rsaProvider;
        }

        public static bool AddCertToStore(
            X509Certificate2 x509,
            StoreName storeName,
            StoreLocation storeLocation)
        {
            try
            {
                X509Store store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Add(x509);
                store.Close();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return false;
            }

            return true;
        }

        public static X509Certificate2 GenerateX509Certificate(string commonName)
        {
            var keyPair = GetAsymmetricCipherKeyPair();

            var certificateGenerator = GetX509V3CertificateGenerator(keyPair);

            // Note: There are more parameters than just commonName
            certificateGenerator.SetSubjectAndIssuer(commonName);

            var bouncyCastleCertificate = GenerateBC(
                keyPair, certificateGenerator);

            var x509 = GenerateX509WithPrivateKey(
                keyPair, bouncyCastleCertificate);
            return x509;
        }

        private static AsymmetricCipherKeyPair GetAsymmetricCipherKeyPair()
        {
            var keyPairGen = new RsaKeyPairGenerator();
            var keyParams = new KeyGenerationParameters(
                new SecureRandom(new CryptoApiRandomGenerator()), 2048);
            keyPairGen.Init(keyParams);

            var keyPair = keyPairGen.GenerateKeyPair();
            return keyPair;
        }

        private static X509V3CertificateGenerator GetX509V3CertificateGenerator(
            AsymmetricCipherKeyPair keyPair)
        {
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
            gen.SetNotAfter(DateTime.Now.AddDays(1));
            gen.SetNotBefore(DateTime.Now.AddDays(-1));
            gen.SetPublicKey(keyPair.Public);

            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            //var ski = new SubjectKeyIdentifier(
            //    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
            //gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, ski);
            var keyUsage = new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
            gen.AddExtension(X509Extensions.KeyUsage, true, keyUsage);

            return gen;
        }

        private static X509Certificate GenerateBC(
            AsymmetricCipherKeyPair keyPair, X509V3CertificateGenerator gen)
        {
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                SignatureAlgorithm, keyPair.Private);

            var bcCert = gen.Generate(sigFact);
            return bcCert;
        }

        private static X509Certificate2 GenerateX509WithPrivateKey(
            AsymmetricCipherKeyPair keyPair,
            X509Certificate bcCert)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var asn1Seq = (Asn1Sequence)Asn1Object.FromByteArray(
                privateKeyInfo.ParsePrivateKey().GetDerEncoded());
            var rsaPrivateKeyStruct = RsaPrivateKeyStructure.GetInstance(asn1Seq);
            var rsa = DotNetUtilities.ToRSA(rsaPrivateKeyStruct);
            var x509Cert = new X509Certificate2(bcCert.GetEncoded());
            return x509Cert.CopyWithPrivateKey(rsa);
        }
    }
}