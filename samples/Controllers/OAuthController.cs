﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using System.Web.Http;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Samples.Controllers
{
    public class OAuthController : Controller
    {
        // GET: /api/oauth/auth?response_type=token&client_id=s6BhdRkqt3&state=xyz&redirect_uri=http://localhost:5000/hello.html
        [HttpGet("api/oauth/auth")]
        public IActionResult auth()
        {
            ClaimsIdentity identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "guoyan"));
            ClaimsPrincipal principal = new ClaimsPrincipal();
            principal.AddIdentity(identity);
            //Context.SignInAsync("oauthserver", principal);

            return SignIn(principal, "OAuth2Server");
        }

        // GET: /api/ouath/token
        [HttpGet]
        public string token()
        {
            return "value";
        }
    }
}
