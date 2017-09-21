using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServerBearer
{
    /// <summary>
    /// Default values used by bearer authentication.
    /// </summary>
    public class OAuthBearerDefaults
    {
        /// <summary>
        /// Default value for AuthenticationScheme property in the JwtBearerAuthenticationOptions
        /// </summary>
        public const string AuthenticationScheme = "Bearer";
    }
}
