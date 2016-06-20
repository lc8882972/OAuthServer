using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.DotNet.InternalAbstractions;
using Samples.Middleware;

namespace Samples
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("config.json", optional: true, reloadOnChange: true);
                //.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsEnvironment("Development"))
            {
                // This will push telemetry data through Application Insights pipeline faster, allowing you to view results immediately.
                builder.AddApplicationInsightsSettings(developerMode: true);
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddApplicationInsightsTelemetry(Configuration);
            services.AddDataProtection();
            services.AddAuthentication();
            services.AddAuthorization();

            services.AddMvcCore();
            
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            app.UseApplicationInsightsRequestTelemetry();
            app.UseApplicationInsightsExceptionTelemetry();

            app.UseStaticFiles();
            app.UseTimeRecorderMiddleware();
            app.UseOAuthServer("oauthserver", option =>
            {
                option.AuthenticationScheme = "oauthserver";
                option.AuthorizationEndpoint = new PathString("/api/oauth/auth");
                option.TokenEndpoint = new PathString("/api/oauth/token");
                option.Events = new OAuthServer.Events.OAuthServerEvents();
                option.Events.OnValidateClientRedirectUri = Provider.OAuthRequestEvents.ValidateClientRedirectUri;
                option.SignInScheme = "oauth";
                option.Scope.Add("name");
                option.Scope.Add("email");
                option.AllowInsecureHttp = true;
                option.ClientId = "smaples";
            });

            app.UseMvc(routes => {
                routes.MapWebApiRoute("defaultapi", "api/{controller}/{action}/{id?}");
            });
            
        }
    }

}
