using OAuthServer.Events;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Samples.Provider
{
    public class OAuthRequestEvents
    {
        public static Task ValidateClientRedirectUri(OAuthServerValidateClientRedirectUriContext context)
        {
            context.Validated();
            return Task.CompletedTask;
        }

        
        public static Task ValidateClientAuthentication(OAuthServerValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.CompletedTask;
        }

        public static Task GrantResourceOwnerCredentials(OAuthServerGrantResourceOwnerCredentialsContext context)
        {
            ClaimsIdentity identity = new ClaimsIdentity(context.Scheme.Name);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            ClaimsPrincipal principal = new ClaimsPrincipal();
            principal.AddIdentity(identity);
            context.Validated(principal);
            return Task.CompletedTask;
        }
    }
}
