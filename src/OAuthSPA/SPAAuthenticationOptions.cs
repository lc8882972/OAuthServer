using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.DataProtection;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;
using System.ComponentModel;
using OAuthSPA.Events;
using Microsoft.AspNetCore.Builder;

namespace OAuthSPA
{
    public class SPAAuthenticationOptions : AuthenticationOptions, IOptions<SPAAuthenticationOptions>
    {
        public SPAAuthenticationOptions()
        {
            SystemClock = new SystemClock();
            AllowInsecureHttp = true;
            ExpireTimeSpan = TimeSpan.FromDays(7);
        }

        public SPAAuthenticationOptions Value
        {
            get
            {
                return this;
            }
        }

        public bool AllowInsecureHttp { get; set; }

        /// <summary>
        /// Controls how much time the cookie will remain valid from the point it is created. The expiration
        /// information is in the protected cookie ticket. Because of that an expired cookie will be ignored 
        /// even if it is passed to the server after the browser should have purged it 
        /// </summary>
        public TimeSpan ExpireTimeSpan { get; set; }

        /// <summary>
        /// The LoginPath property informs the middleware that it should change an outgoing 401 Unauthorized status
        /// code into a 302 redirection onto the given login path. The current url which generated the 401 is added
        /// to the LoginPath as a query string parameter named by the ReturnUrlParameter. Once a request to the
        /// LoginPath grants a new SignIn identity, the ReturnUrlParameter value is used to redirect the browser back  
        /// to the url which caused the original unauthorized status code.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Login", Justification = "By design")]
        public PathString LoginPath { get; set; }

        /// <summary>
        /// If the LogoutPath is provided the middleware then a request to that path will redirect based on the ReturnUrlParameter.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout", Justification = "By design")]
        public PathString LogoutPath { get; set; }

        /// <summary>
        /// The AccessDeniedPath property informs the middleware that it should change an outgoing 403 Forbidden status
        /// code into a 302 redirection onto the given path.
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

        /// <summary>
        /// The ReturnUrlParameter determines the name of the query string parameter which is appended by the middleware
        /// when a 401 Unauthorized status code is changed to a 302 redirect onto the login path. This is also the query 
        /// string parameter looked for when a request arrives on the login path or logout path, in order to return to the 
        /// original url after the action is performed.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "ReturnUrl is the name of a querystring parameter")]
        public string ReturnUrlParameter { get; set; }

        /// <summary>
        /// The TicketDataFormat is used to protect and unprotect the identity and other properties which are stored in the
        /// cookie value. If it is not provided a default data handler is created using the data protection service contained
        /// in the IApplicationBuilder.Properties. The default data protection service is based on machine key when running on ASP.NET, 
        /// and on DPAPI when running in a different process.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; set; }

        /// <summary>
        /// For testing purposes only.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public ISystemClock SystemClock { get; set; }

        /// <summary>
        /// An optional container in which to store the identity across requests. When used, only a session identifier is sent
        /// to the client. This can be used to mitigate potential problems with very large identities.
        /// </summary>
        public ITicketStore SessionStore { get; set; }

        /// <summary>
        /// The Provider may be assigned to an instance of an object created by the application at startup time. The middleware
        /// calls methods on the provider which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        public ISPAAuthenticationEvents Events { get; set; }
    }
}
