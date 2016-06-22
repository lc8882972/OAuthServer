using Microsoft.AspNetCore.Http;

namespace OAuthServer.Events
{
    public class OAuthServerMatchEndpointContext: EndpointContext
    {
        public OAuthServerOptions Options { get; set; }
        /// <summary>
        /// Gets whether or not the endpoint is an OAuth authorize endpoint.
        /// </summary>
        public bool IsAuthorizeEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an OAuth token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        public OAuthServerMatchEndpointContext(HttpContext context, OAuthServerOptions options) : base(context)
        {
            Options = options;
        }
        public void MatchesAuthorizeEndpoint()
        {
            IsAuthorizeEndpoint = true;
            IsTokenEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint()
        {
            IsAuthorizeEndpoint = false;
            IsTokenEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to neither authorize nor token.
        /// </summary>
        public void MatchesNothing()
        {
            IsAuthorizeEndpoint = false;
            IsTokenEndpoint = false;
        }

    }
}
