using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    public class OAuthValidateAuthorizeRequestContext:BaseValidatingContext<OAuthServerOptions>
    {
        /// <summary>
        /// Gets OAuth authorization request data.
        /// </summary>
        public AuthorizeEndpointRequest AuthorizeRequest { get; private set; }

        /// <summary>
        /// Gets data about the OAuth client. 
        /// </summary>
        public OAuthServerValidateClientRedirectUriContext ClientContext { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthValidateAuthorizeRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizeRequest"></param>
        /// <param name="clientContext"></param>
        public OAuthValidateAuthorizeRequestContext(
            HttpContext context,
            OAuthServerOptions options,
            AuthorizeEndpointRequest authorizeRequest,
            OAuthServerValidateClientRedirectUriContext clientContext) : base(context, options)
        {
            AuthorizeRequest = authorizeRequest;
            ClientContext = clientContext;
        }

    }
}
