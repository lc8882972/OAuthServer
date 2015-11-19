using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Events
{
    /// <summary>
    /// Data object used by TokenEndpointRequest when the "grant_type" is "client_credentials".
    /// </summary>    
    public class TokenEndpointRequestClientCredentials
    {
        /// <summary>
        /// The value passed to the Token endpoint in the "scope" parameter
        /// </summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "This class is just for passing data through.")]
        public IList<string> Scope { get; set; }
    }

}
