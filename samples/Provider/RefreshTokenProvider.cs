using OAuthServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using OAuthServer.Events;

namespace Samples.Provider
{
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n"));
            return Task.CompletedTask;
        }

        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }
    }
}
