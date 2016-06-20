using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public class OAuthServerEndpointContext : EndpointContext<OAuthServerOptions>
    {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public OAuthServerEndpointContext(
            HttpContext context,
            OAuthServerOptions options,
            AuthorizeEndpointRequest authorizeRequest)
            : base(context, options)
        {
            AuthorizeRequest = authorizeRequest;
        }

        /// <summary>
        /// Gets OAuth authorization request data.
        /// </summary>
        public AuthorizeEndpointRequest AuthorizeRequest { get; private set; }
    }

}
