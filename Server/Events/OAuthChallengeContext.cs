﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    /// <summary>
    /// Specifies the HTTP response header for the bearer authentication scheme.
    /// </summary>
    public class OAuthChallengeContext : BaseContext<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// Initializes a new <see cref="OAuthRequestTokenContext"/>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="challenge">The www-authenticate header value.</param>
        public OAuthChallengeContext(
            HttpContext context, 
            AuthenticationScheme scheme, 
            AuthenticationSchemeOptions options,
            string challenge)
            : base(context, scheme,options)
        {
            Challenge = challenge;
        }

        /// <summary>
        /// The www-authenticate header value.
        /// </summary>
        public string Challenge { get; protected set; }
    }

}
