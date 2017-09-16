using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    public class OAuthServerGrantRefreshTokenContext: BaseValidatingTicketContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthGrantRefreshTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="clientId"></param>
        public OAuthServerGrantRefreshTokenContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            AuthenticationTicket ticket,
            string clientId) : base(context, scheme, options, ticket)
        {
            ClientId = clientId;
        }

        /// <summary>
        /// The OAuth client id.
        /// </summary>
        public string ClientId { get; private set; }
    }
}
