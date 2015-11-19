using OAuthServer.Events;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Samples.Provider
{
    public class OAuthRequestEvents
    {
        public static Task ValidateClientRedirectUri(OAuthServerValidateClientRedirectUriContext context)
        {
            context.Validated();
            return Task.FromResult<object>(null);
        }
    }
}
