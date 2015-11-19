using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.Framework.OptionsModel;
using OAuthServer;

namespace Microsoft.AspNet.Builder
{
    public static class OAuthServerExtensions
    {
        /// <summary> 
        /// Authenticate users using OAuth. 
        /// </summary> 
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to the configure method.</param> 
        /// <param name="options">The middleware configuration options.</param> 
        /// <returns>The updated <see cref="IApplicationBuilder"/>.</returns> 
        public static IApplicationBuilder UseOAuthServer(this IApplicationBuilder app, string authenticationScheme, Action<OAuthServerOptions> configureOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }


            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }
            var options = new OAuthServerOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }
            return app.UseOAuthServer(options);

        }
        /// <summary> 
        /// Adds the <see cref="OAuthMiddleware{TOptions}"/> middleware to the specified <see cref="IApplicationBuilder"/>, which enables OAuth 2.0 authentication capabilities. 
        /// </summary> 
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param> 
        /// <param name="options">A <see cref="OAuthOptions"/> that specifies options for the middleware.</param> 
        /// <returns>A reference to this instance after the operation has completed.</returns> 
        public static IApplicationBuilder UseOAuthServer(this IApplicationBuilder app, OAuthServerOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            return app.UseMiddleware<OAuthServerMiddleware<OAuthServerOptions>>(options);
        }
    }
}
