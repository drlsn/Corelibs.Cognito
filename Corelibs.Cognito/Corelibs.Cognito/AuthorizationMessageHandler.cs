using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;

namespace Corelibs.Cognito;

public class AuthorizationMessageHandler : DelegatingHandler
{
    private readonly IAuthentication _auth;

    public AuthorizationMessageHandler(IAuthentication auth)
    {
        _auth = auth;
    }

    private AuthenticationHeaderValue _cachedHeader;
    private JwtSecurityToken _accessToken;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_accessToken == null || DateTime.UtcNow > _accessToken.ValidTo)
        {
            _accessToken = await _auth.GetAccessToken();
            if (_accessToken == null)
                throw new NoAccessTokenAvailableException("Access token couldn't be obtained.");

            _cachedHeader = new AuthenticationHeaderValue("Bearer", _accessToken.RawData);
        }

        // We don't try to handle 401s and retry the request with a new token automatically since that would mean we need to copy the request
        // headers and buffer the body and we expect that the user instead handles the 401s. (Also, we can't really handle all 401s as we might
        // not be able to provision a token without user interaction).
        request.Headers.Authorization = _cachedHeader;

        return await base.SendAsync(request, cancellationToken);
    }
}