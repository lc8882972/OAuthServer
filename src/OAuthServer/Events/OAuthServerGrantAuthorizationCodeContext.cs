using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerGrantAuthorizationCodeContext: BaseValidatingTicketContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthGrantAuthorizationCodeContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        public OAuthServerGrantAuthorizationCodeContext(HttpContext context, OAuthServerOptions options,AuthenticationTicket ticket) : base(context, options, ticket)
        {
        }

    }
}
