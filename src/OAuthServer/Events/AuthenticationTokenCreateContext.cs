using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    public class AuthenticationTokenCreateContext : BaseContext<OAuthServerOptions>
    {
        private readonly ISecureDataFormat<AuthenticationTicket> _secureDataFormat;

         public AuthenticationTokenCreateContext( 
             HttpContext context, 
             AuthenticationScheme scheme, 
             OAuthServerOptions options,
             ISecureDataFormat<AuthenticationTicket> secureDataFormat,
             AuthenticationTicket ticket)
             : base(context, scheme, options)
        { 
             _secureDataFormat = secureDataFormat; 
             Ticket = ticket; 
         } 
 
 
         public string Token { get; protected set; } 
 
         public AuthenticationTicket Ticket { get; protected set; } 

 
         public string SerializeTicket()
         { 
             return _secureDataFormat.Protect(Ticket); 
         } 
 
         public void SetToken(string tokenValue)
         { 
             Token = tokenValue; 
         } 

    }
}
