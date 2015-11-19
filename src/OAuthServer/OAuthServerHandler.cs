using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Framework.Logging;
using System.Text;
using System.Globalization;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.AspNet.Http.Authentication;
using System.IO;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;
using Microsoft.AspNet.Authentication;
using OAuthServer.Events;
using Microsoft.AspNet.WebUtilities;

namespace OAuthServer
{
    public class OAuthServerHandler<TOptions> : AuthenticationHandler<TOptions> where TOptions : OAuthServerOptions
    {
                               
        private AuthorizeEndpointRequest _authorizeEndpointRequest;
        private OAuthServerValidateClientRedirectUriContext _clientContext;
        private AuthenticationTicket ticket;


        protected override Task HandleSignInAsync(SignInContext context)
        {
            AuthenticationProperties properties = new AuthenticationProperties();
            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            properties.IssuedUtc = currentUtc;
            properties.ExpiresUtc = currentUtc.Add(Options.AuthorizationCodeExpireTimeSpan);

            // associate client_id with all subsequent tickets
            properties.Items[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;

            if (!string.IsNullOrEmpty(_authorizeEndpointRequest.RedirectUri))
            {
                // keep original request parameter for later comparison
                properties.RedirectUri = _authorizeEndpointRequest.RedirectUri;
            }
            ticket =new AuthenticationTicket(context.Principal,properties, Options.AuthenticationScheme);

            return Task.FromResult<AuthenticationTicket>(ticket);
        }

        protected override Task HandleSignOutAsync(SignOutContext context)
        {
            throw new NotImplementedException();
        }
        protected override async Task FinishResponseAsync()
        {
            // only successful results of an authorize request are altered
            if (_clientContext == null || _authorizeEndpointRequest == null || Response.StatusCode != 200 || ticket==null)
            {
                return;
            }
            // only apply with signin of matching authentication type
            var returnParameter = new Dictionary<string, string>();

            string token = Options.TicketDataFormat.Protect(ticket);
            if (_authorizeEndpointRequest.IsAuthorizationCodeGrantType)
            {
                if (string.IsNullOrEmpty(token))
                {
                    var errorContext = new OAuthValidateAuthorizeRequestContext(Context, Options, _authorizeEndpointRequest, _clientContext);
                    errorContext.SetError(Constants.Errors.UnsupportedResponseType);
                    await SendErrorRedirectAsync(_clientContext, errorContext);
                    return;
                }

                var authResponseContext = new OAuthServerEndpointResponseContext(Context,Options, ticket, _authorizeEndpointRequest, null,token);

                await Options.Events.AuthorizationEndpointResponse(authResponseContext);

                foreach (var parameter in authResponseContext.AdditionalResponseParameters)
                {
                    returnParameter[parameter.Key] = parameter.Value.ToString();
                }

                returnParameter[Constants.Parameters.Code] = token;

                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State))
                {
                    returnParameter[Constants.Parameters.State] = _authorizeEndpointRequest.State;
                }

                string location = string.Empty;
                if (_authorizeEndpointRequest.IsFormPostResponseMode)
                {
                    location = Options.FormPostEndpoint.ToString();
                    returnParameter[Constants.Parameters.RedirectUri] = _clientContext.RedirectUri;
                }
                else
                {
                    location = _clientContext.RedirectUri;
                }

                foreach (var key in returnParameter.Keys)
                {
                    location = Microsoft.AspNet.WebUtilities.QueryHelpers.AddQueryString(location, key, returnParameter[key]);
                }
                Response.Redirect(location);

            }
            else if (_authorizeEndpointRequest.IsImplicitGrantType)
            {
                string location = _clientContext.RedirectUri;

                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                ticket.Properties.IssuedUtc = currentUtc;
                ticket.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

                // associate client_id with access token
                ticket.Properties.Items[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;
             
                DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;

                var appender = new Appender(location, '#');
                appender.Append(Constants.Parameters.AccessToken, token).Append(Constants.Parameters.TokenType, Constants.TokenTypes.Bearer);
                if (accessTokenExpiresUtc.HasValue)
                {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long)(expiresTimeSpan.Value.TotalSeconds + .5);
                    appender.Append(Constants.Parameters.ExpiresIn, expiresIn.ToString(CultureInfo.InvariantCulture));
                }
                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State))
                {
                    appender.Append(Constants.Parameters.State, _authorizeEndpointRequest.State);
                }
                var authResponseContext = new OAuthServerEndpointResponseContext( Context, Options,ticket,_authorizeEndpointRequest,token, null);

                await Options.Events.AuthorizationEndpointResponse(authResponseContext);

                if (Options.SessionStore != null)
                {
                   await  Options.SessionStore.StoreAsync(ticket);
                }
                foreach (var parameter in authResponseContext.AdditionalResponseParameters)
                {
                    appender.Append(parameter.Key, parameter.Value.ToString());
                }

                Response.Redirect(appender.ToString());
            }
          
        }
        protected override Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            throw new NotImplementedException();
        }

        public async override Task<bool> InvokeAsync()
        {
            OAuthServerMatchEndpointContext matchContext = new OAuthServerMatchEndpointContext(Context, Options);
            if ( Options.AuthorizationEndpoint == Request.Path)
            {
                matchContext.MatchesAuthorizeEndpoint();
            }
            else if (Options.TokenEndpoint == Request.Path)
            {
                matchContext.MatchesTokenEndpoint();
            }
            await Options.Events.MatchEndpoint(matchContext);

            if (matchContext.IsRequestCompleted)
            {
                return true;
            }
            if (matchContext.IsAuthorizeEndpoint || matchContext.IsTokenEndpoint)
            {
                if (!Options.AllowInsecureHttp && String.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (matchContext.IsAuthorizeEndpoint)
                {
                    return await InvokeAuthorizeEndpointAsync();
                }
                if (matchContext.IsTokenEndpoint)
                {
                    await InvokeTokenEndpointAsync();
                    return true;
                }
            }
            return false;


        }
        public async Task<bool> InvokeAuthorizeEndpointAsync()
        {
            var authorizeRequest = new AuthorizeEndpointRequest(Request.Query);
            var clientContext = new OAuthServerValidateClientRedirectUriContext( Context,Options,authorizeRequest.ClientId, authorizeRequest.RedirectUri);

            if (!String.IsNullOrEmpty(authorizeRequest.RedirectUri))
            {
                bool acceptableUri = true;
                Uri validatingUri;
                if (!Uri.TryCreate(authorizeRequest.RedirectUri, UriKind.Absolute, out validatingUri))
                {
                    // The redirection endpoint URI MUST be an absolute URI
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!String.IsNullOrEmpty(validatingUri.Fragment))
                {
                    // The endpoint URI MUST NOT include a fragment component.
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!Options.AllowInsecureHttp &&
                    String.Equals(validatingUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    // The redirection endpoint SHOULD require the use of TLS
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2.1
                    acceptableUri = false;
                }
                if (!acceptableUri)
                {
                    clientContext.SetError(Constants.Errors.InvalidRequest);
                    return await SendErrorRedirectAsync(clientContext, clientContext);
                }
            }

            await Options.Events.ValidateClientRedirectUri(clientContext);

            if (!clientContext.IsValidated)
            {
                return await SendErrorRedirectAsync(clientContext, clientContext);
            }


            var validatingContext = new OAuthValidateAuthorizeRequestContext(Context, Options,authorizeRequest,clientContext);
            if (string.IsNullOrEmpty(authorizeRequest.ResponseType))
            {
                validatingContext.SetError(Constants.Errors.InvalidRequest);
            }
            else if (!authorizeRequest.IsAuthorizationCodeGrantType && !authorizeRequest.IsImplicitGrantType)
            {
                validatingContext.SetError(Constants.Errors.UnsupportedResponseType);
            }
            else
            {
                await Options.Events.ValidateAuthorizeRequest(validatingContext);
            }

            if (!validatingContext.IsValidated)
            {
                // an invalid request is not processed further
                return await SendErrorRedirectAsync(clientContext, validatingContext);
            }

            _clientContext = clientContext;
            _authorizeEndpointRequest = authorizeRequest;

            var authorizeEndpointContext = new OAuthServerEndpointContext(Context, Options, authorizeRequest);

            await Options.Events.AuthorizeEndpoint(authorizeEndpointContext);

            return authorizeEndpointContext.IsRequestCompleted;
        }
        public async  Task<bool> InvokeTokenEndpointAsync()
        {
              
            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            // remove milliseconds in case they don't round-trip
            currentUtc = currentUtc.Subtract(TimeSpan.FromMilliseconds(currentUtc.Millisecond));

            Microsoft.AspNet.Http.IFormCollection form = await Request.ReadFormAsync();

            var clientContext = new OAuthServerValidateClientAuthenticationContext(Context,Options,form);

            await Options.Events.ValidateClientAuthentication(clientContext);

            if (!clientContext.IsValidated)
            {
                //_logger.WriteError("clientID is not valid.");
                if (!clientContext.HasError)
                {
                    clientContext.SetError(Constants.Errors.InvalidClient);
                }
                await SendErrorAsJsonAsync(clientContext);
                return true;
            }

            var tokenEndpointRequest = new TokenEndpointRequest(form);

            var validatingContext = new OAuthServerValidateTokenRequestContext(Context, Options, tokenEndpointRequest, clientContext);

            AuthenticationTicket ticket = null;
            if (tokenEndpointRequest.IsAuthorizationCodeGrantType)
            {
                // Authorization Code Grant http://tools.ietf.org/html/rfc6749#section-4.1
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.1.3
                ticket = await InvokeTokenEndpointAuthorizationCodeGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsResourceOwnerPasswordCredentialsGrantType)
            {
                // Resource Owner Password Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.3
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.3.2
                ticket = await InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsClientCredentialsGrantType)
            {
                // Client Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.4
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.4.2
                ticket = await InvokeTokenEndpointClientCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsRefreshTokenGrantType)
            {
                // Refreshing an Access Token
                // http://tools.ietf.org/html/rfc6749#section-6
                ticket = await InvokeTokenEndpointRefreshTokenGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsCustomExtensionGrantType)
            {
                // Defining New Authorization Grant Types
                // http://tools.ietf.org/html/rfc6749#section-8.3
                ticket = await InvokeTokenEndpointCustomGrantAsync(validatingContext, currentUtc);
            }
            else
            {
                // Error Response http://tools.ietf.org/html/rfc6749#section-5.2
                // The authorization grant type is not supported by the
                // authorization server.
                //_logger.WriteError("grant type is not recognized");
                validatingContext.SetError(Constants.Errors.UnsupportedGrantType);
            }

            if (ticket == null)
            {
                await SendErrorAsJsonAsync(validatingContext);
                return false;
            }

            ticket.Properties.IssuedUtc = currentUtc;
            ticket.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

            var tokenEndpointContext = new OAuthServerTokenEndpointContext( Context,Options,ticket,tokenEndpointRequest);

            await Options.Events.TokenEndpoint(tokenEndpointContext);

            if (tokenEndpointContext.TokenIssued)
            {
                ticket = new AuthenticationTicket(tokenEndpointContext.Principal, tokenEndpointContext.Properties, tokenEndpointContext.Options.AuthenticationScheme);
            }
            else
            {
                //_logger.WriteError("Token was not issued to tokenEndpointContext");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                await SendErrorAsJsonAsync(validatingContext);
                return false;
            }

            var accessTokenContext = new AuthenticationTokenCreateContext(Context,Options.AccessTokenFormat,ticket);

            await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            string accessToken = accessTokenContext.Token;
            if (string.IsNullOrEmpty(accessToken))
            {
                accessToken = accessTokenContext.SerializeTicket();
            }
            DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;

            var refreshTokenCreateContext = new AuthenticationTokenCreateContext(
                Context,
                Options.RefreshTokenFormat,
                accessTokenContext.Ticket);
            await Options.RefreshTokenProvider.CreateAsync(refreshTokenCreateContext);
            string refreshToken = refreshTokenCreateContext.Token;

            var tokenEndpointResponseContext = new OAuthTokenEndpointResponseContext(
                Context,
                Options,
                ticket,
                tokenEndpointRequest,
                accessToken,
                tokenEndpointContext.AdditionalResponseParameters);

            await Options.Events.TokenEndpointResponse(tokenEndpointResponseContext);

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory)))
            {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.AccessToken);
                writer.WriteValue(accessToken);
                writer.WritePropertyName(Constants.Parameters.TokenType);
                writer.WriteValue(Constants.TokenTypes.Bearer);
                if (accessTokenExpiresUtc.HasValue)
                {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long)expiresTimeSpan.Value.TotalSeconds;
                    if (expiresIn > 0)
                    {
                        writer.WritePropertyName(Constants.Parameters.ExpiresIn);
                        writer.WriteValue(expiresIn);
                    }
                }
                if (!String.IsNullOrEmpty(refreshToken))
                {
                    writer.WritePropertyName(Constants.Parameters.RefreshToken);
                    writer.WriteValue(refreshToken);
                }
                foreach (var additionalResponseParameter in tokenEndpointResponseContext.AdditionalResponseParameters)
                {
                    writer.WritePropertyName(additionalResponseParameter.Key);
                    writer.WriteValue(additionalResponseParameter.Value);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray();
            }
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Add("Cache-Control", "no-cache");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "-1");
            Response.ContentLength = memory.ToArray().Length;
            await Response.Body.WriteAsync(body,0,body.Length);
            return true;
    }
        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The MemoryStream is Disposed by the StreamWriter")]
        private Task SendErrorAsJsonAsync(BaseValidatingContext<OAuthServer.OAuthServerOptions> validatingContext)
        {
            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory)))
            {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.Error);
                writer.WriteValue(error);
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    writer.WritePropertyName(Constants.Parameters.ErrorDescription);
                    writer.WriteValue(errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri))
                {
                    writer.WritePropertyName(Constants.Parameters.ErrorUri);
                    writer.WriteValue(errorUri);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray();
            }
            Response.StatusCode = 400;
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Add("Cache-Control", "no-cache");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "-1");
            Response.Headers.Add("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            return Response.Body.WriteAsync(body,0,body.Length);
        }
        private async Task<AuthenticationTicket> InvokeTokenEndpointAuthorizationCodeGrantAsync(OAuthServerValidateTokenRequestContext validatingContext,DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var authorizationCodeContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.AuthorizationCodeFormat,
                tokenEndpointRequest.AuthorizationCodeGrant.Code);

            await Options.AuthorizationCodeProvider.ReceiveAsync(authorizationCodeContext);

            AuthenticationTicket ticket = authorizationCodeContext.Ticket;

            if (ticket == null)
            {
                //_logger.WriteError("invalid authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc)
            {
                //_logger.WriteError("expired authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string clientId;
            if (!ticket.Properties.Items.TryGetValue(Constants.Extra.ClientId, out clientId) ||
                !String.Equals(clientId, validatingContext.ClientContext.ClientId, StringComparison.Ordinal))
            {
                //_logger.WriteError("authorization code does not contain matching client_id");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string redirectUri;
            if (ticket.Properties.Items.TryGetValue(Constants.Extra.RedirectUri, out redirectUri))
            {
                ticket.Properties.Items.Remove(Constants.Extra.RedirectUri);
                if (!String.Equals(redirectUri, tokenEndpointRequest.AuthorizationCodeGrant.RedirectUri, StringComparison.Ordinal))
                {
                    //_logger.WriteError("authorization code does not contain matching redirect_uri");
                    validatingContext.SetError(Constants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Events.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthServerGrantAuthorizationCodeContext(
                Context, Options, ticket);

            if (validatingContext.IsValidated)
            {
                await Options.Events.GrantAuthorizationCode(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(
            OAuthServerValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Events.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthServerGrantResourceOwnerCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.UserName,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Password,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Scope);

            if (validatingContext.IsValidated)
            {
                await Options.Events.GrantResourceOwnerCredentials(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointClientCredentialsGrantAsync(
            OAuthServerValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Events.ValidateTokenRequest(validatingContext);
            if (!validatingContext.IsValidated)
            {
                return null;
            }

            var grantContext = new OAuthServerGrantClientCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ClientCredentialsGrant.Scope);

            await Options.Events.GrantClientCredentials(grantContext);

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnauthorizedClient);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointRefreshTokenGrantAsync(
            OAuthServerValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var refreshTokenContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.RefreshTokenFormat,
                tokenEndpointRequest.RefreshTokenGrant.RefreshToken);

            await Options.RefreshTokenProvider.ReceiveAsync(refreshTokenContext);

            AuthenticationTicket ticket = refreshTokenContext.Ticket;

            if (ticket == null)
            {
                //_logger.WriteError("invalid refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc)
            {
                //_logger.WriteError("expired refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            await Options.Events.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthServerGrantRefreshTokenContext(Context, Options, ticket, validatingContext.ClientContext.ClientId);

            if (validatingContext.IsValidated)
            {
                await Options.Events.GrantRefreshToken(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointCustomGrantAsync(
            OAuthServerValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Events.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthServerGrantCustomExtensionContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.GrantType,
                tokenEndpointRequest.CustomExtensionGrant.Parameters);

            if (validatingContext.IsValidated)
            {
                await Options.Events.GrantCustomExtension(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnsupportedGrantType);
        }

        private static AuthenticationTicket ReturnOutcome(
            OAuthServerValidateTokenRequestContext validatingContext,
            BaseValidatingContext<OAuthServerOptions> grantContext,
            AuthenticationTicket ticket,
            string defaultError)
        {
            if (!validatingContext.IsValidated)
            {
                return null;
            }

            if (!grantContext.IsValidated)
            {
                if (grantContext.HasError)
                {
                    validatingContext.SetError(
                        grantContext.Error,
                        grantContext.ErrorDescription,
                        grantContext.ErrorUri);
                }
                else
                {
                    validatingContext.SetError(defaultError);
                }
                return null;
            }

            if (ticket == null)
            {
                validatingContext.SetError(defaultError);
                return null;
            }

            return ticket;
        }


        private Task<bool> SendErrorRedirectAsync(OAuthServerValidateClientRedirectUriContext clientContext,BaseValidatingContext<OAuthServerOptions> validatingContext)
        {
            if (clientContext == null)
            {
                throw new ArgumentNullException("clientContext");
            }

            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            if (!clientContext.IsValidated)
            {
                // write error in response body if client_id or redirect_uri have not been validated
                return SendErrorPageAsync(error, errorDescription, errorUri);
            }

            // redirect with error if client_id and redirect_uri have been validated
            string location = Microsoft.AspNet.WebUtilities.QueryHelpers.AddQueryString(clientContext.RedirectUri, Constants.Parameters.Error, error);
            if (!string.IsNullOrEmpty(errorDescription))
            {
                location = Microsoft.AspNet.WebUtilities.QueryHelpers.AddQueryString(location, Constants.Parameters.ErrorDescription, errorDescription);
            }
            if (!string.IsNullOrEmpty(errorUri))
            {
                location = Microsoft.AspNet.WebUtilities.QueryHelpers.AddQueryString(location, Constants.Parameters.ErrorUri, errorUri);
            }
            Response.Redirect(location);
            // request is handled, does not pass on to application
            return Task.FromResult(true);
        }

        protected override Task<AuthenticationTicket> HandleAuthenticateAsync()
        {
            throw new NotImplementedException();
        }

        private async Task<bool> SendErrorPageAsync(string error, string errorDescription, string errorUri)
        {
            Response.StatusCode = 400;
            Response.Headers.Add("Cache-Control", "no-cache");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "-1");

            if (Options.ApplicationCanDisplayErrors)
            {
                Context.Items.Add("oauth.Error", error);
                Context.Items.Add("oauth.ErrorDescription", errorDescription);
                Context.Items.Add("oauth.ErrorUri", errorUri);
                // request is not handled - pass through to application for rendering
                return false;
            }

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new StreamWriter(memory))
            {
                writer.WriteLine("error: {0}", error);
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    writer.WriteLine("error_description: {0}", errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri))
                {
                    writer.WriteLine("error_uri: {0}", errorUri);
                }
                writer.Flush();
                body = memory.ToArray();
            }

            Response.ContentType = "text/plain;charset=UTF-8";
            Response.Headers.Add("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            await Response.Body.WriteAsync(body,0,body.Length);
            // request is handled, does not pass on to application
            return true;
        }

        private class Appender
        {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter)
            {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value)
            {
                _sb.Append(_hasDelimiter ? '&' : _delimiter).Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString()
            {
                return _sb.ToString();
            }
        }

    }

}
