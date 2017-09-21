using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServerBearer.Events
{
    public class OAuthBearerAuthenticationEvents : IOAuthBearerAuthenticationEvents
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthBearerAuthenticationEvents"/> class
        /// </summary>
        public OAuthBearerAuthenticationEvents()
        {
            OnRequestToken = context => Task.FromResult<object>(null);
            OnValidateIdentity = context => Task.FromResult<object>(null);
            OnApplyChallenge = context =>
            {
                context.Response.Headers.Add("WWW-Authenticate", "invalid");
                return Task.FromResult(0);
            };
        }

        /// <summary>
        /// Handles processing OAuth bearer token.
        /// </summary>
        public Func<OAuthRequestTokenContext, Task> OnRequestToken { get; set; }

        /// <summary>
        /// Handles validating the identity produced from an OAuth bearer token.
        /// </summary>
        public Func<OAuthValidateIdentityContext, Task> OnValidateIdentity { get; set; }

        /// <summary>
        /// Handles applying the authentication challenge to the response message.
        /// </summary>
        public Func<OAuthChallengeContext, Task> OnApplyChallenge { get; set; }

        /// <summary>
        /// Handles processing OAuth bearer token.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual Task RequestToken(OAuthRequestTokenContext context)
        {
            return OnRequestToken(context);
        }

        /// <summary>
        /// Handles validating the identity produced from an OAuth bearer token.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            return OnValidateIdentity.Invoke(context);
        }

        /// <summary>
        /// Handles applying the authentication challenge to the response message.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task ApplyChallenge(OAuthChallengeContext context)
        {
            return OnApplyChallenge(context);
        }
    }
}
