using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using OAuthServer.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;

namespace OAuthServer
{
    public class OAuthServerOptions : AuthenticationOptions
    {
        public OAuthServerOptions()
        {
            Scope = new List<string>();
            AuthorizationCodeExpireTimeSpan = TimeSpan.FromMinutes(5);
            AccessTokenExpireTimeSpan = TimeSpan.FromDays(7);
            SystemClock = new SystemClock();
            AllowInsecureHttp = true;
        }
        /// <summary>
        /// Gets or sets the <see cref="IOAuthServerAuthenticationNotifications"/> used to handle authentication events.
        /// </summary>
        public OAuthServer.Events.OAuthServerEvents Events { get; set; }
        /// <summary> 
        /// Gets or sets the provider-assigned client id. 
        /// </summary> 
        public string ClientId { get; set; }
        /// <summary> 
        /// Gets or sets the provider-assigned client secret. 
        /// </summary> 
        public string ClientSecret { get; set; }
        /// <summary>
        /// Gets or sets the URI where the client will be redirected to authenticate.
        /// </summary>
        public PathString AuthorizationEndpoint { get; set; }
        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the OAuth token.
        /// </summary>
        public PathString TokenEndpoint { get; set; }
        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string DisplayName
        {
            get { return Description.DisplayName; }
            set { Description.DisplayName = value; }
        }

        public bool AllowInsecureHttp { get; set; }
        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }
        /// <summary> 
        /// Gets or sets the authentication scheme corresponding to the middleware 
        /// responsible of persisting user's identity after a successful authentication. 
        /// This value typically corresponds to a cookie middleware registered in the Startup class. 
        public string SignInScheme { get; set; }
        /// <summary>
        /// Produces a bearer token the client application will typically be providing to resource server as the authorization bearer 
        /// http request header. If not provided the token produced on the server's default data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public IAuthenticationTokenProvider AccessTokenProvider { get; set; }
        /// <summary>
        /// The period of time the authorization code remains valid after being issued. The default is five minutes.
        /// This time span must also take into account clock synchronization between servers in a web farm, so a very 
        /// brief value could result in unexpectedly expired tokens.
        /// </summary>
        public TimeSpan AuthorizationCodeExpireTimeSpan { get; set; }
        /// <summary>
        /// The data format used to protect and unprotect the information contained in the refresh token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> RefreshTokenFormat { get; set; }
        /// <summary>
        /// The data format used to protect and unprotect the information contained in the authorization code. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AuthorizationCodeFormat { get; set; }
        /// <summary>
        /// Produces a single-use authorization code to return to the client application. For the OAuth server to be secure the
        /// application MUST provide an instance for AuthorizationCodeProvider where the token produced by the OnCreate or OnCreateAsync event 
        /// is considered valid for only one call to OnReceive or OnReceiveAsync. 
        /// </summary>
        public IAuthenticationTokenProvider AuthorizationCodeProvider { get; set; }
        /// <summary>
        /// The data format used to protect the information contained in the access token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        public ISystemClock SystemClock { get; set; }
        /// <summary>
        /// Produces a refresh token which may be used to produce a new access token when needed. If not provided the authorization server will
        /// not return refresh tokens from the /Token endpoint.
        /// </summary>
        public IAuthenticationTokenProvider RefreshTokenProvider { get; set; }
        /// <summary>
        /// The period of time the access token remains valid after being issued. The default is twenty minutes.
        /// The client application is expected to refresh or acquire a new access token after the token has expired. 
        /// </summary>
        public TimeSpan AccessTokenExpireTimeSpan { get; set; }
        /// <summary>
        /// Set to true if the web application is able to render error messages on the /Authorize endpoint. This is only needed for cases where
        /// the browser is not redirected back to the client application, for example, when the client_id or redirect_uri are incorrect. The 
        /// /Authorize endpoint should expect to see "oauth.Error", "oauth.ErrorDescription", "oauth.ErrorUri" properties added to the owin environment.
        /// </summary>
        public bool ApplicationCanDisplayErrors { get; set; }
        /// <summary>
        /// Endpoint responsible for Form Post Response Mode
        /// See also, http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        /// </summary>
        public PathString FormPostEndpoint { get; set; }

        public ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; set; }

        /// <summary>
        /// 保存token
        /// </summary>
        public Infrastructure.IAuthenticationSessionStore SessionStore { get; set; }

        /// <summary> 
        /// If set this will be used by the CookieAuthenticationMiddleware for data protection. 
        /// </summary> 
        public IDataProtectionProvider DataProtectionProvider { get; set; }

    }
}
