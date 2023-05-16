using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Common.Basic.Collections;
using Common.Basic.Functional;
using Corelibs.Basic.Auth;
using Corelibs.Basic.Net;
using Corelibs.Basic.Storage;
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
            IConfiguration configuration,
            ISecureStorage secureStorage)
        {
            _cognitoService = cognitoService;
            _configuration = configuration;
            _secureStorage = secureStorage;
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
            if (DateTime.UtcNow > _accessToken.ValidTo)
            {
                Console.WriteLine($"Couldn't login because received token has expired");
                return false;
            }

            await _secureStorage.SetAsync(AccessTokenKey, response.AuthenticationResult.AccessToken);

            //Console.WriteLine($"Result Challenge is : {response.ChallengeName}");
            //Console.WriteLine($"Access token valid from : {_accessToken.ValidFrom} to {_accessToken.ValidTo}");

            return true;
        }

        public async Task<bool> SignOut()
        {
            ClearAccessToken();
            return true;

            //var accessToken = await GetAccessToken();
            //if (accessToken is null)
            //{
            //    Console.WriteLine($"Couldn't logout, because not logged in");
            //    return false;
            //}

            //var authRequest = new GlobalSignOutRequest
            //{
            //    AccessToken = accessToken.RawPayload
            //};

            //var response = await _cognitoService.GlobalSignOutAsync(authRequest);
            //if (!response.HttpStatusCode.IsSuccess())
            //{
            //    Console.WriteLine($"Couldn't logout due to network issues");
            //    return false;
            //}

            //if (!_secureStorage.Remove(AccessTokenKey))
            //    Console.WriteLine($"Logout successful, but couldn't clear stored access token");

            //return true;
        }

        public async Task<bool> IsSignedIn()
        {
            if (await GetAccessToken() is null)
                return false;

            return true;
        }

        public async Task<JwtSecurityToken> GetAccessToken()
        {
            if (!_accessToken.IsNull() && DateTime.UtcNow < _accessToken.ValidTo)
                return _accessToken;

            var accessTokenStr = await _secureStorage.GetAsync(AccessTokenKey);
            if (accessTokenStr.IsNullOrEmpty())
                return null;

            _accessToken = new JwtSecurityToken(accessTokenStr);
            if (DateTime.UtcNow > _accessToken.ValidTo)
            {
                _accessToken = null;
                return null;
            }

            return _accessToken;
        }

        public async Task<string> GetAccessTokenRaw()
        {
            _accessToken = await GetAccessToken();
            if (_accessToken.IsNull())
                return string.Empty;

            return _accessToken.RawPayload;
        }

        private void ClearAccessToken()
        {
            _accessToken = null;
            if (!_secureStorage.Remove(AccessTokenKey))
                Console.WriteLine($"Logout successful, but couldn't clear stored access token");
        }
    }
}
