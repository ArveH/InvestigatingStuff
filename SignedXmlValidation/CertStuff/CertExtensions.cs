using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace SignedXmlValidation.CertStuff
{
    public static class CertExtensions
    {
        public static void SetSubjectAndIssuer(this X509V3CertificateGenerator gen,
            string commonName = null,
            string country = null,
            string organizationalUnit = null,
            string locality = null,
            string email = null
        )
        {
            IDictionary attrs = new Hashtable();
            if (commonName != null) attrs[X509Name.CN] = commonName;
            if (country != null) attrs[X509Name.C] = country;
            if (organizationalUnit != null) attrs[X509Name.O] = organizationalUnit;
            if (locality != null) attrs[X509Name.L] = locality;
            if (email != null) attrs[X509Name.E] = email;

            IList ord = new ArrayList();
            if (commonName != null) ord.Add(X509Name.CN);
            if (country != null) ord.Add(X509Name.C);
            if (organizationalUnit != null) ord.Add(X509Name.O);
            if (locality != null) ord.Add(X509Name.L);
            if (email != null) ord.Add(X509Name.E);

            gen.SetSubjectDN(new X509Name(ord, attrs));
            gen.SetIssuerDN(new X509Name(ord, attrs));
        }
    }
}