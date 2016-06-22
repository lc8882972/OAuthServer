using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using OAuthServer.Events;

namespace OAuthServer.Infrastructure
{
    public interface IAuthenticationTokenProvider
    {
        Task CreateAsync(AuthenticationTokenCreateContext context);
        Task ReceiveAsync(AuthenticationTokenReceiveContext context);
    }
}
