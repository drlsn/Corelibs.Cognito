using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Common.Basic.Collections;
using Common.Basic.Functional;
using Corelibs.Basic.Net;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace Corelibs.Cognito
{
    public class CognitoAuthentication : IAuthentication
    {
        private const string AccessTokenKey = "AccessToken";

        private readonly IConfiguration _configuration;
        private readonly IAmazonCognitoIdentityProvider _cognitoService;
        private readonly ISecureStorage _secureStorage;

        private JwtSecurityToken _accessToken;

        public CognitoAuthentication(
            IAmazonCognitoIdentityProvider cognitoService,
            IConfiguration configuration)
        {
            _cognitoService = cognitoService;
            _configuration = configuration;
        }

        public async Task<bool> SignIn(string username, string password)
        {
            if (await IsSignedIn())
            {
                Console.WriteLine($"Couldn't login, because already logged in");
                return false;
            }

            var clientId = _configuration.GetSection("AWS:Cognito:ClientId").Value;

            var authParameters = new Dictionary<string, string>()
            {
                { "USERNAME", username },
                { "PASSWORD", password },
            };

            var authRequest = new InitiateAuthRequest
            {
                ClientId = clientId,
                AuthParameters = authParameters,
                AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
            };
            
            var response = await _cognitoService.InitiateAuthAsync(authRequest);
            if (!response.HttpStatusCode.IsSuccess())
            {
                Console.WriteLine($"Couldn't login due to network issues");
                return false;
            }

            _accessToken = new JwtSecurityToken(response.AuthenticationResult.AccessToken);
            if (_accessToken.ValidTo > DateTime.Now)
            {
                Console.WriteLine($"Couldn't login because received token has expired");
                return false;
            }

            await _secureStorage.SetAsync(AccessTokenKey, response.AuthenticationResult.AccessToken);

            Console.WriteLine($"Result Challenge is : {response.ChallengeName}");
            Console.WriteLine($"Access token valid from : {_accessToken.ValidFrom} to {_accessToken.ValidTo}");

            return true;
        }

        public async Task<bool> SignOut()
        {
            var accessToken = await GetAccessToken();
            if (accessToken is null)
            {
                Console.WriteLine($"Couldn't logout, because not logged in");
                return false;
            }

            var authRequest = new GlobalSignOutRequest
            {
                AccessToken = accessToken.RawPayload
            };

            var response = await _cognitoService.GlobalSignOutAsync(authRequest);
            if (!response.HttpStatusCode.IsSuccess())
            {
                Console.WriteLine($"Couldn't logout due to network issues");
                return false;
            }

            if (!_secureStorage.Remove(AccessTokenKey))
                Console.WriteLine($"Logout successful, but couldn't clear stored access token");

            return true;
        }

        public async Task<bool> IsSignedIn()
        {
            if (await GetAccessToken() is null)
                return false;

            return true;
        }

        public async Task<JwtSecurityToken> GetAccessToken()
        {
            if (!_accessToken.IsNull() && _accessToken.ValidTo < DateTime.Now)
                return _accessToken;

            var accessTokenStr = await _secureStorage.GetAsync(AccessTokenKey);
            if (accessTokenStr.IsNullOrEmpty() || _accessToken.ValidTo > DateTime.Now)
                return null;

            _accessToken = new JwtSecurityToken(accessTokenStr);

            return _accessToken;
        }

        public async Task<string> GetAccessTokenRaw()
        {
            if (!_accessToken.IsNull() && _accessToken.ValidTo < DateTime.Now)
                return _accessToken.RawPayload;

            var accessTokenStr = await _secureStorage.GetAsync(AccessTokenKey);
            if (accessTokenStr.IsNullOrEmpty() || _accessToken.ValidTo > DateTime.Now)
                return string.Empty;

            _accessToken = new JwtSecurityToken(accessTokenStr);

            return accessTokenStr;
        }

    }
}
