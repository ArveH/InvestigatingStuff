using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SignedXmlValidation.CertStuff;
using Xunit;

namespace SignedXmlTester
{
    public class CertTester
    {
        [Fact]
        public void TestCreateCaCertificate()
        {
            var x509 = CertCreator.GenerateCACertificate("For Testing");
            
            // Add to store
            x509.FriendlyName = "ah-root-CA";
            CertCreator.AddCertToStore(x509, StoreName.Root, StoreLocation.CurrentUser);
            
            x509.HasPrivateKey.Should().BeTrue();
        }
    }
}