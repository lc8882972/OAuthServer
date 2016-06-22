using System;
using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using OAuthSPA.Events;


namespace OAuthSPA
{
    public class SPAAuthenticationHandler : AuthenticationHandler<SPAAuthenticationOptions>
    {
        private AuthenticationTicket ticket;
        private bool notLoginUrl = true;

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.Fail("Does not support authenticate"));
        }

        public override Task<bool> HandleRequestAsync()
        {
            if (Options.LoginPath.Equals(Request.Path, StringComparison.OrdinalIgnoreCase))
            {
                notLoginUrl = false;
            }
            return Task.FromResult<bool>(false);
        }
        protected override async Task HandleSignInAsync(SignInContext context)
        {
            var signInContext = new SPASigningInContext(
                Context,
                Options,
                Options.AuthenticationScheme,
                context.Principal,
                new AuthenticationProperties(context.Properties));

            DateTimeOffset issuedUtc;
            if (signInContext.Properties.IssuedUtc.HasValue)
            {
                issuedUtc = signInContext.Properties.IssuedUtc.Value;
            }
            else
            {
                issuedUtc = Options.SystemClock.UtcNow;
                signInContext.Properties.IssuedUtc = issuedUtc;
            }

            if (!signInContext.Properties.ExpiresUtc.HasValue)
            {
                signInContext.Properties.ExpiresUtc = issuedUtc.Add(Options.ExpireTimeSpan);
            }

            await Options.Events.SigningIn(signInContext);

            AuthenticationProperties properties = new AuthenticationProperties();
            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            properties.IssuedUtc = currentUtc;
            properties.ExpiresUtc = currentUtc.Add(Options.ExpireTimeSpan);

            ticket = new AuthenticationTicket(context.Principal, properties, Options.AuthenticationScheme);

            var signedInContext = new SPASignedInContext(
                Context,
                Options,
                Options.AuthenticationScheme,
                signInContext.Principal,
                signInContext.Properties);

            await Options.Events.SignedIn(signedInContext);

        }

        protected override async Task HandleSignOutAsync(SignOutContext context)
        {
            if (!Context.User.Identity.IsAuthenticated)
            {
                return;
            }
            if (Options.SessionStore != null)
            {
                await Options.SessionStore.RemoveAsync(Context.User.Identity.Name);
            }

            var sinoutContext = new SPASigningOutContext(
                Context,
                Options);

            await Options.Events.SigningOut(sinoutContext);
        }

        protected override Task<bool> HandleForbiddenAsync(ChallengeContext context)
        {
            return base.HandleForbiddenAsync(context);
        }

        protected override Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            return base.HandleUnauthorizedAsync(context);
        }

        protected override async Task FinishResponseAsync()
        {
            // only successful results of an authorize request are altered
            if (Response.StatusCode != 200 || ticket == null || notLoginUrl)
            {
                return;
            }

            string token = Options.TicketDataFormat.Protect(ticket);

            if (Options.SessionStore != null)
            {
                await Options.SessionStore.StoreAsync(ticket);
            }
            TimeSpan? expiresTimeSpan = ticket.Properties.ExpiresUtc - ticket.Properties.IssuedUtc;
            long expire = Convert.ToInt64(expiresTimeSpan.Value.TotalSeconds);
            AccessTokenModel ak = new AccessTokenModel() { AccessToken = token, ExpiresIn = expire, TokenType = "Bearer" };
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Add("Cache-Control", "no-cache");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "-1");
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(ak);
            byte[] buff = System.Text.Encoding.UTF8.GetBytes(json);
            Response.ContentLength = buff.Length;
            await Response.Body.WriteAsync(buff, 0, buff.Length);
            return;
        }

        private class AccessTokenModel
        {
            public string AccessToken { get; set; }
            public string TokenType { get; set; }
            public long ExpiresIn { get; set; }
        }
    }
}
