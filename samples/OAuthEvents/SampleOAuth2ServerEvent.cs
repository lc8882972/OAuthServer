using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Samples.OAuthEvents
{
    public class SampleOAuth2ServerEvent : OAuthServer.Events.OAuthServerEvents
    {
        private ILogger<SampleOAuth2ServerEvent> logger;
        public SampleOAuth2ServerEvent(ILoggerFactory factory)
        {
            this.logger = factory.CreateLogger<SampleOAuth2ServerEvent>();
            this.OnValidateClientAuthentication = context =>
            {
                context.Validated();
                return Task.CompletedTask;
            };

            this.OnValidateClientRedirectUri = context =>
            {
                context.Validated();
                return Task.CompletedTask;
            };

            this.OnGrantResourceOwnerCredentials = context =>
            {
                ClaimsIdentity identity = new ClaimsIdentity(context.Scheme.Name);
                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                ClaimsPrincipal principal = new ClaimsPrincipal();
                principal.AddIdentity(identity);
                context.Validated(principal);
                return Task.CompletedTask;
            };
        }
    }
}
