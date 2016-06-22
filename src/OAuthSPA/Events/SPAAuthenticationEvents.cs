using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OAuthSPA.Events
{
    /// <summary>
    /// This default implementation of the ISPAAuthenticationEvents may be used if the 
    /// application only needs to override a few of the interface methods. This may be used as a base class
    /// or may be instantiated directly.
    /// </summary>
    public class SPAAuthenticationEvents:ISPAAuthenticationEvents
    {
        /// <summary>
        /// A delegate assigned to this property will be invoked when the related method is called.
        /// </summary>
        public Func<SPAValidatePrincipalContext, Task> OnValidatePrincipal { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// A delegate assigned to this property will be invoked when the related method is called.
        /// </summary>
        public Func<SPASigningInContext, Task> OnSigningIn { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// A delegate assigned to this property will be invoked when the related method is called.
        /// </summary>
        public Func<SPASignedInContext, Task> OnSignedIn { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// A delegate assigned to this property will be invoked when the related method is called.
        /// </summary>
        public Func<SPASigningOutContext, Task> OnSigningOut { get; set; } = context => Task.FromResult(0);

        private static bool IsAjaxRequest(HttpRequest request)
        {
            return string.Equals(request.Query["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal) ||
                string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal);
        }

        /// <summary>
        /// Implements the interface method by invoking the related delegate method.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual Task ValidatePrincipal(SPAValidatePrincipalContext context) => OnValidatePrincipal(context);

        /// <summary>
        /// Implements the interface method by invoking the related delegate method.
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SigningIn(SPASigningInContext context) => OnSigningIn(context);

        /// <summary>
        /// Implements the interface method by invoking the related delegate method.
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SignedIn(SPASignedInContext context) => OnSignedIn(context);

        /// <summary>
        /// Implements the interface method by invoking the related delegate method.
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SigningOut(SPASigningOutContext context) => OnSigningOut(context);
    }
}
