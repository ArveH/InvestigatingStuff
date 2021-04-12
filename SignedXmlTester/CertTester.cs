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
            var cert = CertCreator.GenerateX509Certificate("For Testing");
            cert.HasPrivateKey.Should().BeTrue();
        }
    }
}