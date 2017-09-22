﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using OAuthServer.Events;
using Samples.OAuthEvents;

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
            // Add framework services
            services.AddAuthorization();

            services.AddSingleton<IOAuthServerEvents, SampleOAuth2ServerEvent>();
            services.AddAuthentication(f=> 
            {
                f.DefaultAuthenticateScheme = "Bearer";
                f.DefaultChallengeScheme = "Bearer";
                f.DefaultForbidScheme = "Bearer";
            })
            .AddOAuthServer("OAuth2Server", "OAuth2", option =>
              {
                  option.AuthorizationEndpoint = new PathString("/api/oauth/auth");
                  option.TokenEndpoint = new PathString("/api/oauth/token");
                  option.Scope.Add("name");
                  option.Scope.Add("email");
                  option.AllowInsecureHttp = true;
                  option.ClientId = "smaples";
                  option.AccessTokenExpireTimeSpan = TimeSpan.FromDays(7);
                  option.RefreshTokenProvider = new Provider.RefreshTokenProvider();
              })
              .AddOAuthBearer(o=> {
                  //o.Provider = new OAuthBearerProvider();
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
            //app.UseTimeRecorderMiddleware();

            app.UseMvc(routes =>
            {
                routes.MapWebApiRoute("defaultapi", "api/{controller}/{action}/{id?}");
            });

        }
    }

}
