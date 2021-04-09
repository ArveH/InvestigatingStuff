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
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignedXmlValidation.CertStuff
{
    public class CertCreator
    {
        private const string SignatureAlgorithm = "SHA256WithRSA";

        public static X509Certificate2 GenerateX509Certificate()
        {
            var keyPair = GetAsymmetricCipherKeyPair();

            var certificateGenerator = GetX509V3CertificateGenerator(keyPair);

            var bouncyCastleCertificate = GenerateBouncyCastleCertificate(
                keyPair, certificateGenerator);

            return GenerateX509CertificateWithPrivateKey(
                keyPair, bouncyCastleCertificate);
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
            gen.SetSubjectAndIssuer(commonName: "For Testing");
            gen.SetNotAfter(DateTime.Now.AddDays(1));
            gen.SetNotBefore(DateTime.Now.AddDays(-1));
            gen.SetPublicKey(keyPair.Public);

            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            var ski = new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, ski);
            var keyUsage = new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
            gen.AddExtension(X509Extensions.KeyUsage, true, keyUsage);
            return gen;
        }

        private static X509Certificate GenerateBouncyCastleCertificate(
            AsymmetricCipherKeyPair keyPair, X509V3CertificateGenerator gen)
        {
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                SignatureAlgorithm, keyPair.Private);

            var bcCert = gen.Generate(sigFact);
            return bcCert;
        }

        private static X509Certificate2 GenerateX509CertificateWithPrivateKey(
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