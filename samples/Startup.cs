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
using Samples.Middleware;
using OAuthServer.Events;

namespace Samples
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("config.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsEnvironment("Development"))
            {
                // This will push telemetry data through Application Insights pipeline faster, allowing you to view results immediately.
                //builder.AddApplicationInsightsSettings(developerMode: true);
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {

            // Add framework services.
            //services.AddApplicationInsightsTelemetry(Configuration);
            services.AddDataProtection();

            services.AddAuthorization();
            services.AddAuthentication()
                .AddOAuthServer("OAuth2Server", "OAuth2", option =>
              {
                  OAuthServerEvents events = new OAuthServerEvents();

                  events.OnValidateClientRedirectUri = Provider.OAuthRequestEvents.ValidateClientRedirectUri;
                  option.AuthorizationEndpoint = new PathString("/api/oauth/auth");
                  option.TokenEndpoint = new PathString("/api/oauth/token");
                  option.Events = events;
                  option.SignInScheme = "oauth";
                  option.Scope.Add("name");
                  option.Scope.Add("email");
                  option.AllowInsecureHttp = true;
                  option.ClientId = "smaples";
              }).AddJwtBearer("OAuth2ServerBearer", "OAuth2", options=> {
                
              });
            services.AddMvcCore()
               .AddAuthorization()
               .AddDataAnnotations()
               .AddFormatterMappings()
               .AddJsonFormatters();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseAuthentication();
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseTimeRecorderMiddleware();

            app.UseMvc(routes =>
            {
                routes.MapWebApiRoute("defaultapi", "api/{controller}/{action}/{id?}");
            });

        }
    }

}
