using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OAuthSPA.Events
{
    /// <summary>
    /// Context object passed to the ISPAAuthenticationEvents method SignedIn.
    /// </summary> 
    public class SPASigningOutContext: BaseSPAContext
    {
        /// <summary>
        /// Context object passed to the ISPAAuthenticationEvents method SignedIn.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="options">The middleware options</param>
        public SPASigningOutContext(HttpContext context, SPAAuthenticationOptions options)
            : base(context, options)
        {
            
        }
    }
}
