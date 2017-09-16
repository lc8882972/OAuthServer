using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    /// <summary>
    /// Contains the authentication ticket data from an OAuth bearer token.
    /// </summary>
    public class OAuthValidateIdentityContext : BaseValidatingTicketContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthValidateIdentityContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        public OAuthValidateIdentityContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            AuthenticationTicket ticket) : base(context, scheme, options, ticket)
        {
        }
    }

}
