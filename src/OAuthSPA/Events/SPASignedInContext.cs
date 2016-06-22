using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace OAuthSPA.Events
{
    /// <summary>
    /// Context object passed to the ISPAAuthenticationEvents method SignedIn.
    /// </summary>  
    public class SPASignedInContext:BaseSPAContext
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="options">The middleware options</param>
        /// <param name="authenticationScheme">Initializes AuthenticationScheme property</param>
        /// <param name="principal">Initializes Principal property</param>
        /// <param name="properties">Initializes Properties property</param>
        public SPASignedInContext(
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
        /// Contains the claims that were converted into the outgoing cookie.
        /// </summary>
        public ClaimsPrincipal Principal { get; private set; }

        /// <summary>
        /// Contains the extra data that was contained in the outgoing cookie.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}
