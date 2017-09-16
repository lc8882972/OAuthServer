using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Samples.Controllers
{
    [Route("api/[controller]")]
    public class LoginController : ApiBaseController
    {
        // GET: api/values
        [HttpGet]
        public IActionResult Get()
        {
            ClaimsIdentity identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "guoyan"));
            ClaimsPrincipal principal = new ClaimsPrincipal();
            principal.AddIdentity(identity);
            Context.Authentication.SignInAsync("SPA", principal);
            return Ok();
        }

    }
}
