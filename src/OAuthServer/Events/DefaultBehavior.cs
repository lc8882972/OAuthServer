using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    internal static class DefaultBehavior
    {
        internal static readonly Func<OAuthValidateAuthorizeRequestContext, Task> ValidateAuthorizeRequest = context =>
        {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OAuthServerValidateTokenRequestContext, Task> ValidateTokenRequest = context =>
        {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OAuthServerGrantAuthorizationCodeContext, Task> GrantAuthorizationCode = context =>
        {
            if (context.Ticket != null && context.Ticket.Principal != null && context.Ticket.Principal.Identity.IsAuthenticated)
            {
                context.Validated();
            }
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OAuthServerGrantRefreshTokenContext, Task> GrantRefreshToken = context =>
        {
            if (context.Ticket != null && context.Ticket.Principal != null && context.Ticket.Principal.Identity.IsAuthenticated)
            {
                context.Validated();
            }
            return Task.FromResult<object>(null);
        };
    }

}
