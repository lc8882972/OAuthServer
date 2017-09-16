using System;
using Microsoft.Extensions.Options;
using OAuthServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OAuthExtensions
    {
        public static AuthenticationBuilder AddOAuthServer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OAuthServerOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuthServerOptions>, PostConfigureOAuthServerAuthenticationOptions>());
            return builder.AddScheme<OAuthServerOptions, OAuthServerHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}