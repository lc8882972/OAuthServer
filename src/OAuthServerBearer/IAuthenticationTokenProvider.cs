using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using OAuthServerBearer.Events;

namespace OAuthServerBearer
{
    public interface IAuthenticationTokenProvider
    {
        Task CreateAsync(AuthenticationTokenCreateContext context);
        Task ReceiveAsync(AuthenticationTokenReceiveContext context);
    }
}
