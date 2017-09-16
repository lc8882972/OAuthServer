using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace OAuthServer.Events
{
    /// <summary>
    /// Context object passed to the ICookieAuthenticationEvents method SignedIn.
    /// </summary>  
    public class OAuthServerSignedInContext : PrincipalContext<OAuthServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="principal">Initializes Principal property</param>
        /// <param name="properties">Initializes Properties property</param>
        /// <param name="options">The handler options</param>
        public OAuthServerSignedInContext(
            HttpContext context,
            AuthenticationScheme scheme,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            OAuthServerOptions options)
            : base(context, scheme, options, properties)
        {
            Principal = principal;
        }
    }
}
