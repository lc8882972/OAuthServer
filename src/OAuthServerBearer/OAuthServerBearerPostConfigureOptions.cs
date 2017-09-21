using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServerBearer
{
    public class OAuthServerBearerPostConfigureOptions : IPostConfigureOptions<OAuthServerBearerOptions>
    {
        private readonly IDataProtectionProvider _dp;
        public OAuthServerBearerPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        public void PostConfigure(string name, OAuthServerBearerOptions options)
        {
            var provider = _dp;
            if (options.AccessTokenFormat == null)
            {
                IDataProtector dataProtector = provider.CreateProtector("OAuth2", "Access_Token", "v2");
                options.AccessTokenFormat = new TicketDataFormat(dataProtector);
            }
           
        }
    }
}
