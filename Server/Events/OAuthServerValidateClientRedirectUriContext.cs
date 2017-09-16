using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerValidateClientRedirectUriContext: BaseValidatingClientContext<OAuthServerOptions>
    {
        public OAuthServerValidateClientRedirectUriContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions optios,
            string clientId,
            string redirectUri) : base(context, scheme, optios, clientId)
        {
            RedirectUri = redirectUri;
        }
        /// <summary>
        /// Gets the client redirect URI
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "redirect_uri is a string parameter")]
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Marks this context as validated by the application. IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns></returns>
        public override bool Validated()
        {
            if (String.IsNullOrEmpty(RedirectUri))
            {
                // Don't allow default validation when redirect_uri not provided with request
                return false;
            }

            return base.Validated();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="RedirectUri"/>.
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings", MessageId = "0#", Justification = "redirect_uri is a string parameter")]
        public bool Validated(string redirectUri)
        {
            if (redirectUri == null)
            {
                throw new ArgumentNullException("redirectUri");
            }

            if (!String.IsNullOrEmpty(RedirectUri) &&
                !String.Equals(RedirectUri, redirectUri, StringComparison.Ordinal))
            {
                // Don't allow validation to alter redirect_uri provided with request
                return false;
            }

            RedirectUri = redirectUri;

            return Validated();
        }

    }

}
