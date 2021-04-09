using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Security.Cryptography.X509Certificates;

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
            gen.SetNotAfter(DateTime.Now.AddDays(1));
            gen.SetNotBefore(DateTime.Now.AddDays(-1));
            gen.SetPublicKey(keypair.Public);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            ISignatureFactory sigFact = new Asn1SignatureFactory(
                signatureAlgorithm, keypair.Private);

            var bcCert = gen.Generate(sigFact);

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keypair.Private);

            var asn1Seq = (Asn1Sequence)Asn1Object.FromByteArray(privateKeyInfo.ParsePrivateKey().GetDerEncoded());
            var rsaPrivKeyStruct = RsaPrivateKeyStructure.GetInstance(asn1Seq);
            //var rsaParams = new RsaPrivateCrtKeyParameters(
            //    rsaPrivKeyStruct.Modulus,
            //    rsaPrivKeyStruct.PublicExponent,
            //    rsaPrivKeyStruct.PrivateExponent,
            //    rsaPrivKeyStruct.Prime1,
            //    rsaPrivKeyStruct.Prime2,
            //    rsaPrivKeyStruct.Exponent1,
            //    rsaPrivKeyStruct.Exponent2,
            //    rsaPrivKeyStruct.Coefficient);

            //var rsa = DotNetUtilities.ToRSA(rsaParams);
            var rsa = DotNetUtilities.ToRSA(rsaPrivKeyStruct);
            var x509Cert = new X509Certificate2(bcCert.GetEncoded());
            return x509Cert.CopyWithPrivateKey(rsa);
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


            var cert = certGen.Generate(sigFact);

            cert.CheckValidity();
            cert.Verify(rsaPublic);

            var x509Cert = new X509Certificate2(cert.GetEncoded());

            var rsa = DotNetUtilities.ToRSA(rsaPrivate);
            return x509Cert.CopyWithPrivateKey(rsa);
        }
    }
}