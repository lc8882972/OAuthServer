using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;

namespace Samples.Middleware
{
    // You may need to install the Microsoft.AspNet.Http.Abstractions package into your project
    public class OrderMiddleware
    {
        private readonly RequestDelegate _next;

        public OrderMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public Task Invoke(HttpContext httpContext)
        {

            return _next(httpContext);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class OrderMiddlewareExtensions
    {
        public static IApplicationBuilder UseOrderMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<OrderMiddleware>();
        }
    }
}
