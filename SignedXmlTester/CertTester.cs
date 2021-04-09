using FluentAssertions;
using SignedXmlValidation.CertStuff;
using Xunit;

namespace SignedXmlTester
{
    public class CertTester
    {
        [Fact]
        public void TestCreateBC509Cert()
        {
            var cert = CertCreator.GenerateX509Certificate();
            cert.HasPrivateKey.Should().BeTrue();
        }
    }
}