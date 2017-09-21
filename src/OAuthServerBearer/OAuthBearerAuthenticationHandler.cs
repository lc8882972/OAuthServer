using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;
using OAuthServerBearer.Events;

namespace OAuthServerBearer
{
    public class OAuthBearerAuthenticationHandler : AuthenticationHandler<OAuthServerBearerOptions>
    {
        public OAuthBearerAuthenticationHandler(
            IOptionsMonitor<OAuthServerBearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new OAuthBearerAuthenticationEvents Events
        {
            get { return (OAuthBearerAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OAuthBearerAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                // Find token in default location
                string requestToken = null;
                string authorization = Request.Headers["Authorization"];

                if (!string.IsNullOrEmpty(authorization))
                {
                    if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        requestToken = authorization.Substring("Bearer ".Length).Trim();
                    }
                }
                // Give application opportunity to find from a different location, adjust, or reject token
                var requestTokenContext = new OAuthRequestTokenContext(
                    this.Context,
                    this.Scheme,
                    this.Options,
                    requestToken);

                await Events.RequestToken(requestTokenContext);

                // If no token found, no further work possible
                if (string.IsNullOrEmpty(requestTokenContext.Token))
                {
                    return AuthenticateResult.NoResult();
                }

                // Call provider to process the token into data
                var tokenReceiveContext = new AuthenticationTokenReceiveContext(
                    this.Context,
                    this.Scheme,
                    this.Options,
                    Options.AccessTokenFormat,
                    requestTokenContext.Token);

                if (Options.AccessTokenProvider != null)
                {
                    await Options.AccessTokenProvider.ReceiveAsync(tokenReceiveContext);
                }

                if (tokenReceiveContext.Ticket == null)
                {
                    tokenReceiveContext.DeserializeTicket(tokenReceiveContext.Token);
                }

                AuthenticationTicket ticket = tokenReceiveContext.Ticket;
                if (ticket == null)
                {
                    Logger.LogWarning("invalid bearer token received");
                    return AuthenticateResult.Fail("invalid bearer token received");
                }

                // Validate expiration time if present
                DateTimeOffset currentUtc = Clock.UtcNow;

                if (ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc.Value < currentUtc)
                {
                    Logger.LogWarning("expired bearer token received");
                    return AuthenticateResult.Fail("expired bearer token received");
                }

                // Give application final opportunity to override results
                var context = new OAuthValidateIdentityContext(Context, Scheme, Options, ticket);
                if (ticket != null &&
                    ticket.Principal != null &&
                    ticket.Principal.Identity.IsAuthenticated)
                {
                    // bearer token with identity starts validated
                    context.Validated();
                }


                await Events.ValidateIdentity(context);

                if (!context.IsValidated)
                {
                    return AuthenticateResult.Fail("Authentication failed");
                }

                // resulting identity values go back to caller
                TokenValidatedContext tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                {
                    Principal = ticket.Principal,
                    SecurityToken = requestToken
                };

                tokenValidatedContext.Success();
                return tokenValidatedContext.Result;
            }
            catch (Exception ex)
            {
                Logger.LogError("Authentication failed", ex);
                return null;
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;

            AuthenticationResponseChallenge challenge = new AuthenticationResponseChallenge(Scheme.Name, properties);
            OAuthChallengeContext challengeContext = new OAuthChallengeContext(Context, Scheme, Options, challenge);
            Events.ApplyChallenge(challengeContext);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Find response challenge details for a specific authentication middleware
        /// </summary>
        /// <param name="authenticationType">The authentication type to look for</param>
        /// <param name="authenticationMode">The authentication mode the middleware is running under</param>
        /// <returns>The information instructing the middleware how it should behave</returns>
        public AuthenticationResponseChallenge LookupChallenge(string authenticationType, AuthenticationMode authenticationMode)
        {
            if (authenticationType == null)
            {
                throw new ArgumentNullException("authenticationType");
            }

            //AuthenticationResponseChallenge challenge = Context.Authentication.GetAuthenticationSchemes()
            //bool challengeHasAuthenticationTypes = challenge != null && challenge.AuthenticationTypes != null && challenge.AuthenticationTypes.Length != 0;
            //if (challengeHasAuthenticationTypes == false)
            //{
            //    return authenticationMode == AuthenticationMode.Active ? (challenge ?? new AuthenticationResponseChallenge(null, null)) : null;
            //}
            //foreach (var challengeType in Context.Authentication.GetAuthenticationSchemes())
            //{
            //    if (string.Equals(challengeType.AuthenticationScheme, authenticationType, StringComparison.Ordinal))
            //    {
            //        return new AuthenticationResponseChallenge;
            //    }
            //}

            return null;
        }
    }
}
