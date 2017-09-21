using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace OAuthServerBearer
{
    public class OAuthServerBearerOptions: AuthenticationSchemeOptions
    {
        public AuthenticationMode AuthenticationMode { get;set; }
        /// <summary>
        /// The TicketDataFormat is used to protect and unprotect the identity and other properties which are stored in the
        /// cookie value. If not provided one will be created using <see cref="DataProtectionProvider"/>.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }
        /// <summary>
        /// Receives the bearer token the client application will be providing to web application. If not provided the token 
        /// produced on the server's default data protection by using the AccessTokenFormat. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthAuthorizationServerOptions.AccessTokenProvider 
        /// and OAuthAuthorizationServerOptions.AccessTokenFormat of the authorization server.
        /// </summary>
        public IAuthenticationTokenProvider AccessTokenProvider { get; set; }
    }
}
