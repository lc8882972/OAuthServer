using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    /// <summary>
    /// Data object used by TokenEndpointRequest which contains parameter information when the "grant_type" is unrecognized.
    /// </summary>
    public class TokenEndpointRequestCustomExtension
    {
        /// <summary>
        /// The parameter information when the "grant_type" is unrecognized.
        /// </summary>
        public IFormCollection Parameters { get; set; }
    }

}
