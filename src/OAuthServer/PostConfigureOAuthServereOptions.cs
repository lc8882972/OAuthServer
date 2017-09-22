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
            var provider = _dp;
            IDataProtector dataProtector = null; 
            if (options.AuthorizationCodeFormat == null)
            {
                dataProtector = provider.CreateProtector("OAuth2", "Authentication_Code", "v2");
                options.AuthorizationCodeFormat = new TicketDataFormat(dataProtector);
            }

            if (options.AccessTokenFormat == null)
            {
                dataProtector = provider.CreateProtector("OAuth2", "Access_Token", "v2");
                options.AccessTokenFormat = new TicketDataFormat(dataProtector);
            }

            if (options.RefreshTokenFormat == null)
            {
                dataProtector = provider.CreateProtector("OAuth2", "Refresh_Token", "v2");
                options.RefreshTokenFormat = new TicketDataFormat(dataProtector);
            }
        }
    }
}
