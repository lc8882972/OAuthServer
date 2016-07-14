using System;
using Microsoft.Extensions.Options;
using OAuthSPA;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Extension methods to add cookie authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class OAuthSPAAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="SPAAuthenticationMiddleware"/> middleware to the specified <see cref="IApplicationBuilder"/>, which enables cookie authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <param name="configureOptions">An action delegate to configure the provided <see cref="SPAAuthenticationOptions"/>.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseSPAAuthentication(this IApplicationBuilder app, Action<SPAAuthenticationOptions> configureOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = new SPAAuthenticationOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }
            return app.UseSPAAuthentication(options);
        }

        /// <summary>
        /// Adds the <see cref="SPAAuthenticationMiddleware"/> middleware to the specified <see cref="IApplicationBuilder"/>, which enables cookie authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <param name="options">A <see cref="SPAAuthenticationOptions"/> that specifies options for the middleware.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseSPAAuthentication(this IApplicationBuilder app, SPAAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<SPAAuthenticationMiddleware>(Options.Create<SPAAuthenticationOptions>(options));
        }
    }
}
