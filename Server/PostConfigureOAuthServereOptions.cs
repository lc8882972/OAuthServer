using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OAuthServer
{
    /// <summary>
    /// Used to setup defaults for all <see cref="OAuthServerOptions"/>.
    /// </summary>
    public class PostConfigureOAuthServerAuthenticationOptions : IPostConfigureOptions<OAuthServerOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public PostConfigureOAuthServerAuthenticationOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        /// <summary>
        /// Invoked to post configure a TOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        public void PostConfigure(string name, OAuthServerOptions options)
        {
            var provider = options.DataProtectionProvider ?? _dp;
            var dataProtector = options.DataProtectionProvider.CreateProtector("OAuthServer.OAuthServerMiddleware", name, "v2");

            options.TicketDataFormat = new TicketDataFormat(dataProtector);

            if (options.Events == null)
            {
                options.Events = new OAuthServer.Events.OAuthServerEvents();
            }
        }
    }
}
