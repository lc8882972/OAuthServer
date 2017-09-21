using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServerBearer.Events
{
    public class AuthenticationTokenReceiveContext : BaseContext<OAuthServerBearerOptions>
    {
        private readonly ISecureDataFormat<AuthenticationTicket> _secureDataFormat;

        public AuthenticationTokenReceiveContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerBearerOptions options,
            ISecureDataFormat<AuthenticationTicket> secureDataFormat,
            string requestToken)
            : base(context, scheme, options)
        {
            if (secureDataFormat == null)
            {
                throw new ArgumentNullException("secureDataFormat");
            }
            if (requestToken == null)
            {
                throw new ArgumentNullException("token");
            }
            _secureDataFormat = secureDataFormat;
            Token = requestToken;
        }

        public string Token { get; protected set; }

        public AuthenticationTicket Ticket { get; protected set; }

        public void DeserializeTicket(string protectedData)
        {
            Ticket = _secureDataFormat.Unprotect(protectedData);
        }

        public void SetTicket(AuthenticationTicket ticket)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }
            Ticket = ticket;
        }
    }
}
