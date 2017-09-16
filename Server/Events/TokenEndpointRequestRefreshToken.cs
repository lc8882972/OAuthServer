using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    /// <summary>
    /// Data object used by TokenEndpointRequest when the "grant_type" parameter is "refresh_token".
    /// </summary>
    public class TokenEndpointRequestRefreshToken
    {
        /// <summary>
        /// The value passed to the Token endpoint in the "refresh_token" parameter
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "scope" parameter
        /// </summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "This is just a data container object.")]
        public IList<string> Scope { get; set; }
    }

}
