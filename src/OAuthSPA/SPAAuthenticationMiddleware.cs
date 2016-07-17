using System;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using OAuthSPA.Events;
using Microsoft.Extensions.Options;

namespace OAuthSPA
{
    public class SPAAuthenticationMiddleware: AuthenticationMiddleware<SPAAuthenticationOptions>
    {
        public SPAAuthenticationMiddleware(
            RequestDelegate next,
            IDataProtectionProvider dataProtectionProvider,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder,
            IOptions<SPAAuthenticationOptions> options)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (dataProtectionProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectionProvider));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            if (urlEncoder == null)
            {
                throw new ArgumentNullException(nameof(urlEncoder));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (Options.Events == null)
            {
                Options.Events = new SPAAuthenticationEvents();
            }

            if (Options.TicketDataFormat == null)
            {
                //var provider = Options.DataProtectionProvider ?? dataProtectionProvider;
                var dataProtector = dataProtectionProvider.CreateProtector(typeof(SPAAuthenticationMiddleware).FullName, Options.AuthenticationScheme, "v2");
                Options.TicketDataFormat = new TicketDataFormat(dataProtector);
            }

            if (!Options.LoginPath.HasValue)
            {
                throw new ArgumentNullException(nameof(Options.LoginPath));
            }
        }

        protected override AuthenticationHandler<SPAAuthenticationOptions> CreateHandler()
        {
            return new SPAAuthenticationHandler();
        }
    }
}
