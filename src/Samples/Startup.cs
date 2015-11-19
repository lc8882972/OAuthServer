using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.DependencyInjection;
using Samples.Middleware;
using Microsoft.Framework.Logging;
using Microsoft.Dnx.Runtime;
using Microsoft.AspNet.Hosting;
using Microsoft.Framework.Configuration;

namespace Samples
{
    public class Startup
    {
        private IConfigurationRoot config_root;
        public Startup(IHostingEnvironment hostEnv,IApplicationEnvironment appEnv,ILoggerFactory loggerFactory)
        {
            var builder = new ConfigurationBuilder();
            builder.SetBasePath(appEnv.ApplicationBasePath);
            builder.AddJsonFile("config.json");
            config_root = builder.Build();
            string redis = config_root["AppSetting:redis"];
        }
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddInstance<IConfigurationRoot>(config_root);
            services.AddAuthentication();
            services.AddAuthorization();
            services.AddCors();
            services.AddMvcCore();
            
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseTimeRecorderMiddleware();
            app.UseOAuthServer("oauthserver",option=> {
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
            // Add the platform handler to the request pipeline.
            //app.UseIISPlatformHandler();
            app.UseWebSockets();
            app.UseMvc(routes => {
                routes.MapWebApiRoute("defaultapi", "api/{controller}/{action}/{id?}");
            });
            
        }
    }

}
