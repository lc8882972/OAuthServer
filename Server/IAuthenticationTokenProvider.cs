using System.Threading.Tasks;
using OAuthServer.Events;

namespace OAuthServer
{
    public interface IAuthenticationTokenProvider
    {
        Task CreateAsync(AuthenticationTokenCreateContext context);
        Task ReceiveAsync(AuthenticationTokenReceiveContext context);
    }
}
