using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Http.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerEndpointResponseContext : EndpointContext<OAuthServerOptions>

    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthServerEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="tokenEndpointRequest"></param>
        public OAuthServerEndpointResponseContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            AuthenticationTicket ticket,
            AuthorizeEndpointRequest authorizeEndpointRequest,
            string accessToken,
            string authorizationCode)
            : base(context, scheme, options)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            Principal = ticket.Principal;
            Properties = ticket.Properties;
            AuthorizeEndpointRequest = authorizeEndpointRequest;
            AdditionalResponseParameters = new Dictionary<string, object>(StringComparer.Ordinal);
            AccessToken = accessToken;
            AuthorizationCode = authorizationCode;
        }

        /// <summary>
        /// Gets the identity of the resource owner.
        /// </summary>
        public ClaimsPrincipal Principal { get; private set; }

        /// <summary>
        /// Dictionary containing the state of the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        /// <summary>
        /// Gets information about the authorize endpoint request. 
        /// </summary>
        public AuthorizeEndpointRequest AuthorizeEndpointRequest { get; private set; }

        /// <summary>
        /// Enables additional values to be appended to the token response.
        /// </summary>
        public IDictionary<string, object> AdditionalResponseParameters { get; private set; }

        /// <summary>
        /// The serialized Access-Token. Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// The created Authorization-Code. Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode { get; private set; }
    }
}
