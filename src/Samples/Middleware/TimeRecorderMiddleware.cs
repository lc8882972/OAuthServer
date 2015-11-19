using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Samples.Middleware
{
    public class TimeRecorderMiddleware
    {
        private RequestDelegate _next;
        private ILogger Logger { get; set; }
        public TimeRecorderMiddleware(RequestDelegate next, ILoggerFactory loggerFactory)
        {
            this._next = next;
            Logger = loggerFactory.CreateLogger(this.GetType().FullName);
        }
        public async Task Invoke(HttpContext context)
        {
            var sw = new Stopwatch();
            sw.Start();
            await _next(context);
            var str = @"url:{0},time:{1}/ms,code:{2}";
            var current_url = context.Request.Scheme + "://" + context.Request.Host + context.Request.Path + context.Request.QueryString;
            var text = string.Format(str, current_url, sw.ElapsedMilliseconds, context.Response.StatusCode);
            Logger.LogInformation(text);
            //await context.Response.WriteAsync(text);
        }
    }
    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class TimeRecorderMiddlewareExtensions
    {
        public static IApplicationBuilder UseTimeRecorderMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TimeRecorderMiddleware>();
        }
    }
}
