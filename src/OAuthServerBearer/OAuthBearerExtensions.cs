using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OAuthServerBearer;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OAuthBearerExtensions
    {
        public static AuthenticationBuilder AddOAuthBearer(this AuthenticationBuilder builder)
             => builder.AddOAuthBearer(OAuthBearerDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddOAuthBearer(this AuthenticationBuilder builder, Action<OAuthServerBearerOptions> configureOptions)
            => builder.AddOAuthBearer(OAuthBearerDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddOAuthBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<OAuthServerBearerOptions> configureOptions)
            => builder.AddOAuthBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddOAuthBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OAuthServerBearerOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuthServerBearerOptions>, OAuthServerBearerPostConfigureOptions>());
            return builder.AddScheme<OAuthServerBearerOptions, OAuthBearerAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
