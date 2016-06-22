using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
    public abstract class EndpointContext : BaseContext
    {
        protected EndpointContext(HttpContext context)
               : base(context)
        {
        }
        public bool IsRequestCompleted { get; private set; }

        public void RequestCompleted()
        {
            IsRequestCompleted = true;
        }
    }
}
