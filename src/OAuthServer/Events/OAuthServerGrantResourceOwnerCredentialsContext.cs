using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    public class OAuthServerGrantResourceOwnerCredentialsContext: BaseValidatingTicketContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthGrantResourceOwnerCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="clientId"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="scope"></param>
        public OAuthServerGrantResourceOwnerCredentialsContext(
            HttpContext context,
            OAuthServerOptions options,
            string clientId,
            string userName,
            string password,
            IList<string> scope)
            : base(context, options, null)
        {
            ClientId = clientId;
            UserName = userName;
            Password = password;
            Scope = scope;
        }

        /// <summary>
        /// OAuth client id.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// Resource owner username.
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Resource owner password.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// List of scopes allowed by the resource owner.
        /// </summary>
        public IList<string> Scope { get; private set; }
    }
}
