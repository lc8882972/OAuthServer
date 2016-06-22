using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    public abstract class BaseValidatingClientContext:BaseValidatingContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientContext(
            HttpContext context,
            OAuthServerOptions options,
            string clientId)
            : base(context, options)
        {
            ClientId = clientId;
        }

        /// <summary>
        /// The "client_id" parameter for the current request. The Authorization Server application is responsible for 
        /// validating this value identifies a registered client.
        /// </summary>
        public string ClientId { get; protected set; }

    }
}
