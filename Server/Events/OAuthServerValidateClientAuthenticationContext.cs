using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public class OAuthServerValidateClientAuthenticationContext : BaseValidatingClientContext<OAuthServerOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthValidateClientAuthenticationContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="parameters"></param>
        public OAuthServerValidateClientAuthenticationContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthServerOptions options,
            IFormCollection parameters)
            : base(context, scheme, options, null)
        {
            Parameters = parameters;
        }

        /// <summary>
        /// Gets the set of form parameters from the request.
        /// </summary>
        public IFormCollection Parameters { get; private set; }

        /// <summary>
        /// Sets the client id and marks the context as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public bool Validated(string clientId)
        {
            ClientId = clientId;

            return Validated();
        }

        /// <summary>
        /// Extracts HTTP basic authentication credentials from the HTTP authenticate header.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1021:AvoidOutParameters", MessageId = "0#", Justification = "Optimized for usage")]
        public bool TryGetBasicCredentials(out string clientId, out string clientSecret)
        {
            // Client Authentication http://tools.ietf.org/html/rfc6749#section-2.3
            // Client Authentication Password http://tools.ietf.org/html/rfc6749#section-2.3.1

            Microsoft.Extensions.Primitives.StringValues authorization;
            Request.Headers.TryGetValue("Authorization", out authorization);
            if (authorization.Count != 0 && authorization.Contains("Basic"))
            {
                try
                {
                    byte[] data = Convert.FromBase64String(authorization[1].Trim());
                    string text = Encoding.UTF8.GetString(data);
                    int delimiterIndex = text.IndexOf(':');
                    if (delimiterIndex >= 0)
                    {
                        clientId = text.Substring(0, delimiterIndex);
                        clientSecret = text.Substring(delimiterIndex + 1);
                        ClientId = clientId;
                        return true;
                    }
                }
                catch (FormatException)
                {
                    // Bad Base64 string
                }
                catch (ArgumentException)
                {
                    // Bad utf-8 string
                }
            }

            clientId = null;
            clientSecret = null;
            return false;
        }

        /// <summary>
        /// Extracts forms authentication credentials from the HTTP request body.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1021:AvoidOutParameters", MessageId = "0#", Justification = "Optimized for usage")]
        public bool TryGetFormCredentials(out string clientId, out string clientSecret)
        {
            clientId = Parameters[Constants.Parameters.ClientId];
            if (!String.IsNullOrEmpty(clientId))
            {
                clientSecret = Parameters[Constants.Parameters.ClientSecret];
                ClientId = clientId;
                return true;
            }
            clientId = null;
            clientSecret = null;
            return false;
        }
    }
}
