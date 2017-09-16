﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerValidateTokenRequestContext : BaseValidatingContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthValidateTokenRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        /// <param name="clientContext"></param>
        public OAuthServerValidateTokenRequestContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            TokenEndpointRequest tokenRequest,
            BaseValidatingClientContext<OAuthServerOptions> clientContext) : base(context, scheme, options)
        {
            TokenRequest = tokenRequest;
            ClientContext = clientContext;
        }

        /// <summary>
        /// Gets the token request data.
        /// </summary>
        public TokenEndpointRequest TokenRequest { get; private set; }

        /// <summary>
        /// Gets information about the client.
        /// </summary>
        public BaseValidatingClientContext<OAuthServerOptions> ClientContext { get; private set; }
    }
}
