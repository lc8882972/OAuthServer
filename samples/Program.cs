using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore;

namespace Samples
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
            .UseContentRoot(Directory.GetCurrentDirectory())
            .ConfigureAppConfiguration(c => c.AddCommandLine(args))
            .ConfigureLogging(f =>
            {

            })
            .UseStartup<Startup>()
            .UseKestrel()
            .UseIISIntegration()
            .Build();
    }
}
