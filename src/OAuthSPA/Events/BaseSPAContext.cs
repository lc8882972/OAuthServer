using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthSPA.Events
{
    public class BaseSPAContext : BaseContext
    {
        public BaseSPAContext(
            HttpContext context,
            SPAAuthenticationOptions options)
            : base(context)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            Options = options;
        }

        public SPAAuthenticationOptions Options { get; }
    }
}
