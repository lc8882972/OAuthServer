using System;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using OAuthSPA.Events;

namespace OAuthSPA
{
    public class SPAAuthenticationMiddleware: AuthenticationMiddleware<SPAAuthenticationOptions>
    {
        public SPAAuthenticationMiddleware(
            RequestDelegate next,
            IDataProtectionProvider dataProtectionProvider,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder,
            SPAAuthenticationOptions options)
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
            //if (!Options.LogoutPath.HasValue)
            //{
            //    Options.LogoutPath = CookieAuthenticationDefaults.LogoutPath;
            //}
            //if (!Options.AccessDeniedPath.HasValue)
            //{
            //    Options.AccessDeniedPath = CookieAuthenticationDefaults.AccessDeniedPath;
            //}
        }

        protected override AuthenticationHandler<SPAAuthenticationOptions> CreateHandler()
        {
            return new SPAAuthenticationHandler();
        }
    }
}
