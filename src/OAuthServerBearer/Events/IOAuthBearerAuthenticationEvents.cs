using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServerBearer.Events
{
    public interface IOAuthBearerAuthenticationEvents
    {
        /// <summary>
        /// Invoked before the <see cref="System.Security.Claims.ClaimsIdentity"/> is created. Gives the application an 
        /// opportunity to find the identity from a different location, adjust, or reject the token.
        /// </summary>
        /// <param name="context">Contains the token string.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task RequestToken(OAuthRequestTokenContext context);

        /// <summary>
        /// Called each time a request identity has been validated by the middleware. By implementing this method the
        /// application may alter or reject the identity which has arrived with the request.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ValidateIdentity(OAuthValidateIdentityContext context);

        /// <summary>
        /// Called each time a challenge is being sent to the client. By implementing this method the application
        /// may modify the challenge as needed.
        /// </summary>
        /// <param name="context">Contains the default challenge.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ApplyChallenge(OAuthChallengeContext context);
    }
}
