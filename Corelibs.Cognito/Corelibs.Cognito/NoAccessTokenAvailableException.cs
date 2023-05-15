using System.Runtime.Serialization;

namespace Corelibs.Cognito
{
    [Serializable]
    internal class NoAccessTokenAvailableException : Exception
    {
        public NoAccessTokenAvailableException(string? message) : base(message)
        {
        }
    }
}