using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthServerBearer.Events
{
    public class TokenValidatedContext : ResultContext<OAuthServerBearerOptions>
    {
        public TokenValidatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerBearerOptions options)
            : base(context, scheme, options) { }

        public string SecurityToken { get; set; }
    }
}
