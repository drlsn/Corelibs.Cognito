using System.Net.Http.Json;
using System.Text.Json;

namespace Corelibs.Cognito
{
    public static class CognitoRequestExtensions
    {
        public static async Task Authenticate(
            this HttpClient client, 
            string url,
            string clientId, 
            string username, 
            string password)
        {
            var authData = new AuthenticationData()
            {
                AuthParameters =
                {
                    USERNAME = username,
                    PASSWORD = password
                },
                AuthFlow = "USER_PASSWORD_AUTH",
                ClientId = clientId
            };

            var response = await client.PostAsJsonAsync(url, authData);
            if (!response.IsSuccessStatusCode)
                return;

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var authResponse = JsonSerializer.Deserialize<AuthenticationResponse>(jsonResponse);

            Console.WriteLine(authResponse.AuthenticationResult.AccessToken);
        }
    }

    internal class AuthenticationData
    {
        public AuthParameters AuthParameters { get; set; }
        public string AuthFlow { get; set; }
        public string ClientId { get; set; }

    }

    internal class AuthParameters
    {
        public string USERNAME;
        public string PASSWORD;
    }

    internal class AuthenticationResponse
    {
        public AuthenticationResult AuthenticationResult { get; set; }
        public ChallengeParameters ChallengeParameters { get; set; }
    }

    internal class AuthenticationResult
    {
        public long ExpiresIn { get; set; }
        public string IdToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; }
    }

    internal class ChallengeParameters
    {

    }
}
