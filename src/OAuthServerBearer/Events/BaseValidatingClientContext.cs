using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServerBearer.Events
{
    public abstract class BaseValidatingClientContext<TOptions> : BaseValidatingContext<TOptions> where TOptions : OAuthServerBearerOptions
    {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientContext(
            HttpContext context,
            AuthenticationScheme scheme,
            TOptions options,
            string clientId)
            : base(context, scheme, options)
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
