using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.DataProtection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.WebEncoders;
using Microsoft.Framework.OptionsModel;
using Microsoft.AspNet.Authentication;

namespace OAuthServer
{
    // You may need to install the Microsoft.AspNet.Http.Abstractions package into your project
    public class OAuthServerMiddleware<TOptions> : AuthenticationMiddleware<TOptions> where TOptions : OAuthServer.OAuthServerOptions, new()
    {
        public OAuthServerMiddleware(
              RequestDelegate next,
              IDataProtectionProvider dataProtectionProvider,
              ILoggerFactory loggerFactory,
              IUrlEncoder encoder,
              TOptions options,
              ConfigureOptions<TOptions> configureOptions = null)
        : base(next, options, loggerFactory, encoder)
        {
            var dataProtector = dataProtectionProvider.CreateProtector(GetType().FullName, Options.AuthenticationScheme, "v1");

            Options.TicketDataFormat = new TicketDataFormat(dataProtector);

            if (Options.Events == null)
            {
                Options.Events = new OAuthServer.Events.OAuthServerEvents();
            }
        }

        protected override AuthenticationHandler<TOptions> CreateHandler()
        {
            return new OAuthServerHandler<TOptions>();
        }
    }
}
