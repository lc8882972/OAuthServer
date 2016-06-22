using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace OAuthServer
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class OAuthServerMiddleware : AuthenticationMiddleware<OAuthServerOptions>
    {
        public OAuthServerMiddleware(
              RequestDelegate next,
              IOptions<OAuthServerOptions> options,
              ILoggerFactory loggerFactory,
              UrlEncoder encoder,
              IDataProtectionProvider dataProtectionProvider
              )
        : base(next, options, loggerFactory, encoder)
        {
            var provider = Options.DataProtectionProvider ?? dataProtectionProvider;
            var dataProtector = provider.CreateProtector(typeof(OAuthServerMiddleware).FullName, Options.AuthenticationScheme, "v2");

            Options.TicketDataFormat = new TicketDataFormat(dataProtector);

            if (Options.Events == null)
            {
                Options.Events = new OAuthServer.Events.OAuthServerEvents();
            }
        }

        protected override AuthenticationHandler<OAuthServerOptions> CreateHandler()
        {
            return new OAuthServerHandler();
        }
    }
}
