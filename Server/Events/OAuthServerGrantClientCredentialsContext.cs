using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerGrantClientCredentialsContext: BaseValidatingTicketContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthGrantClientCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="clientId"></param>
        /// <param name="scope"></param>
        public OAuthServerGrantClientCredentialsContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            string clientId,
            IList<string> scope)
            : base(context, scheme, options, null)
        {
            ClientId = clientId;
            Scope = scope;
        }

        /// <summary>
        /// OAuth client id.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// List of scopes allowed by the resource owner.
        /// </summary>
        public IList<string> Scope { get; private set; }
    }
}
