using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Authentication;

namespace OAuthServer.Events
{
    public class AuthenticationTokenReceiveContext : BaseContext
    {
        private readonly ISecureDataFormat<AuthenticationTicket> _secureDataFormat;

        public AuthenticationTokenReceiveContext(HttpContext context, ISecureDataFormat<AuthenticationTicket> secureDataFormat, string token): base(context)
        {
            if (secureDataFormat == null)
            {
                throw new ArgumentNullException("secureDataFormat");
            }
            if (token == null)
            {
                throw new ArgumentNullException("token");
            }
            _secureDataFormat = secureDataFormat;
            Token = token;

        }


        public string Token { get; protected set; }


        public AuthenticationTicket Ticket { get; protected set; }


        public void SetTicket(AuthenticationTicket ticket)
        {
            Ticket = ticket;
        }

    }
}
