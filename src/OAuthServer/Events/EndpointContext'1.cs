using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Events
{
     /// <summary> 
     /// Base class used for certain event contexts 
     /// </summary> 
     public abstract class EndpointContext<TOptions> : BaseContext
     { 
         /// <summary> 
         /// Creates an instance of this context 
         /// </summary> 
         protected EndpointContext(HttpContext context, TOptions options)
             : base(context) 
         {
            Options = options;
         } 
         
        public TOptions Options { get; set; }

         /// <summary> 
         /// True if the request should not be processed further by other components. 
         /// </summary> 
         public bool IsRequestCompleted { get; private set; } 
 
 
         /// <summary> 
         /// Prevents the request from being processed further by other components.  
         /// IsRequestCompleted becomes true after calling. 
         /// </summary> 
         public void RequestCompleted()
         { 
             IsRequestCompleted = true; 
         } 
     } 

}
