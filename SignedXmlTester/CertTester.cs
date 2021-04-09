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
            var cert = CertCreator.GenerateX509Cert();
            cert.HasPrivateKey.Should().BeTrue();
        }

        [Fact]
        public void TestCreateBC509Cert2()
        {
            var cert = CertCreator.GenerateX509Cert2();
            cert.HasPrivateKey.Should().BeTrue();
        }
    }
}