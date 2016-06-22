using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthSPA.Events
{
    /// <summary>
    /// Context object passed to the ISPAAuthenticationEvents method SigningIn.
    /// </summary>    
    public class SPASigningInContext: BaseSPAContext
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="options">The middleware options</param>
        /// <param name="authenticationScheme">Initializes AuthenticationScheme property</param>
        /// <param name="principal">Initializes Principal property</param>
        /// <param name="properties">Initializes Extra property</param>
        public SPASigningInContext(
            HttpContext context,
            SPAAuthenticationOptions options,
            string authenticationScheme,
            ClaimsPrincipal principal,
            AuthenticationProperties properties)
            : base(context, options)
        {
            AuthenticationScheme = authenticationScheme;
            Principal = principal;
            Properties = properties;
        }

        /// <summary>
        /// The name of the AuthenticationScheme creating a cookie
        /// </summary>
        public string AuthenticationScheme { get; private set; }

        /// <summary>
        /// Contains the claims about to be converted into the outgoing cookie.
        /// May be replaced or altered during the SigningIn call.
        /// </summary>
        public ClaimsPrincipal Principal { get; set; }

        /// <summary>
        /// Contains the extra data about to be contained in the outgoing cookie.
        /// May be replaced or altered during the SigningIn call.
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
