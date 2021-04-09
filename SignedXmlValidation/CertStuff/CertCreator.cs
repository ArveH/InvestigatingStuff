using System;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignedXmlValidation.CertStuff
{
    public class CertCreator
    {
        public static X509Certificate2 GenerateX509Cert2()
        {
            var certName = "Arve";
            var keypairgen = new RsaKeyPairGenerator();
            var keyParams = new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024);
            keypairgen.Init(keyParams);

            var keypair = keypairgen.GenerateKeyPair();

            var gen = new X509V3CertificateGenerator();

            var CN = new X509Name("CN=" + certName);
            var SN = BigInteger.ProbablePrime(120, new Random());

            gen.SetSerialNumber(SN);
            gen.SetSubjectDN(CN);
            gen.SetIssuerDN(CN);
            gen.SetNotAfter(DateTime.MaxValue);
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            gen.SetPublicKey(keypair.Public);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                signatureAlgorithm, keypair.Private);

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keypair.Private);

            var bcCert = gen.Generate(sigFact);
            return new X509Certificate2(bcCert.GetEncoded());
        }

        public static X509Certificate2 GenerateX509Cert()
        {
            BigInteger rsaPubMod = new BigInteger(Base64.Decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
            BigInteger rsaPubExp = new BigInteger(Base64.Decode("EQ=="));
            BigInteger rsaPrivMod = new BigInteger(Base64.Decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
            BigInteger rsaPrivDP = new BigInteger(Base64.Decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
            BigInteger rsaPrivDQ = new BigInteger(Base64.Decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
            BigInteger rsaPrivExp = new BigInteger(Base64.Decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
            BigInteger rsaPrivP = new BigInteger(Base64.Decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
            BigInteger rsaPrivQ = new BigInteger(Base64.Decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
            BigInteger rsaPrivQinv = new BigInteger(Base64.Decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));
            RsaKeyParameters rsaPublic = new RsaKeyParameters(false, rsaPubMod, rsaPubExp);
            RsaPrivateCrtKeyParameters rsaPrivate = new RsaPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);

            IDictionary attrs = new Hashtable();
            attrs[X509Name.C] = "AU";
            attrs[X509Name.O] = "The Legion of the Bouncy Castle";
            attrs[X509Name.L] = "Melbourne";
            attrs[X509Name.ST] = "Victoria";
            attrs[X509Name.E] = "feedback-crypto@bouncycastle.org";

            IList ord = new ArrayList();
            ord.Add(X509Name.C);
            ord.Add(X509Name.O);
            ord.Add(X509Name.L);
            ord.Add(X509Name.ST);
            ord.Add(X509Name.E);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.One);

            certGen.SetIssuerDN(new X509Name(ord, attrs));
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            certGen.SetSubjectDN(new X509Name(ord, attrs));
            certGen.SetPublicKey(rsaPublic);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                signatureAlgorithm, rsaPrivate);


            X509Certificate cert = certGen.Generate(sigFact);

            //			Assert.IsTrue((cert.IsValidNow && cert.Verify(rsaPublic)),"Certificate failed to be valid (RSA)");
            cert.CheckValidity();
            cert.Verify(rsaPublic);

            var x509Cert = new X509Certificate2(cert.GetEncoded());

            var rsa = DotNetUtilities.ToRSA(rsaPrivate);
            return x509Cert.CopyWithPrivateKey(rsa);

            //Console.WriteLine(ASN1Dump.DumpAsString(cert.ToAsn1Object()));

            //ISet dummySet = cert.GetNonCriticalExtensionOids();

            //if (dummySet != null)
            //{
            //    foreach (string key in dummySet)
            //    {
            //        Console.WriteLine("\t{0}:\t{1}", key);
            //    }
            //}

            //Console.WriteLine();

            //dummySet = cert.GetNonCriticalExtensionOids();
            //if (dummySet != null)
            //{
            //    foreach (string key in dummySet)
            //    {
            //        Console.WriteLine("\t{0}:\t{1}", key);
            //    }
            //}

            //Console.WriteLine();
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(
            string subjectName, 
            string issuerName, 
            AsymmetricKeyParameter issuerPrivKey, 
            int keyStrength = 2048)
        {
            var certificate = GetBCCert(
                subjectName, 
                issuerName, 
                keyStrength, 
                out var subjectKeyPair);

            // Corresponding private key
            var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // Merge into X509Certificate2
            var x509 = new X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            var rsaParams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, 
                rsa.PublicExponent, 
                rsa.PrivateExponent, 
                rsa.Prime1, 
                rsa.Prime2, 
                rsa.Exponent1, 
                rsa.Exponent2, 
                rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaParams);
            return x509;
        }


        public static AsymmetricKeyParameter GenerateCACertificate(
            string subjectName, int keyStrength = 2048)
        {
            var certificate = GetBCCert(
                subjectName, 
                subjectName, 
                keyStrength, 
                out var subjectKeyPair);

            var x509 = new X509Certificate2(certificate.GetEncoded());

            // Add CA certificate to Root store
            //addCertToStore(cert, StoreName.Root, StoreLocation.CurrentUser);

            return subjectKeyPair.Private;
        }

        private static X509Certificate GetBCCert(string subjectName, string issuerName, int keyStrength,
            out AsymmetricCipherKeyPair subjectKeyPair)
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
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                signatureAlgorithm, subjectKeyPair.Private);

            // Selfsign certificate
            var certificate = certificateGenerator.Generate(sigFact);
            return certificate;
        }
    }
}