using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    /// <summary>
    /// Specifies the HTTP request header for the bearer authentication scheme.
    /// </summary>
    public class OAuthRequestTokenContext : BaseContext
    {
        /// <summary>
        /// Initializes a new <see cref="OAuthRequestTokenContext"/>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="token">The authorization header value.</param>
        public OAuthRequestTokenContext(
            HttpContext context,
            string token)
            : base(context)
        {
            Token = token;
        }

        /// <summary>
        /// The authorization header value
        /// </summary>
        public string Token { get; set; }
    }

}
