using System.IdentityModel.Tokens.Jwt;

namespace Corelibs.Cognito
{
    public interface IAuthentication
    {
        Task<bool> SignIn(string username, string password);
        Task<bool> SignOut();

        Task<bool> IsSignedIn();
        Task<JwtSecurityToken> GetAccessToken();
        Task<string> GetAccessTokenRaw();
    }
}
