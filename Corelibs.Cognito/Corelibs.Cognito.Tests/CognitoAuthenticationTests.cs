using Amazon.CognitoIdentityProvider;
using Microsoft.Extensions.Configuration;
using NSubstitute;

namespace Corelibs.Cognito.Tests
{
    public class CognitoAuthenticationTests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public async Task IsSignedIn_ShouldBeFalse_IfNotSignedInBefore()
        {
            var cognito = Substitute.For<IAmazonCognitoIdentityProvider>();
            var config = Substitute.For<IConfiguration>();
            var storage = Substitute.For<ISecureStorage>();
            
            storage.GetAsync(Arg.Any<string>()).Returns("");

            var auth = new CognitoAuthentication(cognito, config, storage);

            Assert.IsFalse(await auth.IsSignedIn());
        }
    }
}
