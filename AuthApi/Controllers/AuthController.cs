using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using AuthApi.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NLog;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {

        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        public AuthController()
        {
            
        }
        
        [HttpPost("[action]")]
        public IActionResult Login(string username, string pwd)
        {
            if (AuthUtil.IsValidLogin(username, pwd))
            {
                var token = AuthUtil.GenerateToken(username);
                return new ObjectResult(token);
            }
            return BadRequest();
        }

        [HttpGet("[action]"), Authorize(Roles = "user,admin")]
        public string Test()
        {
            try
            {
                // if (Request.Headers.TryGetValue("Authorization", out var headerValue))
                // {
                //     var handler = new JwtSecurityTokenHandler();
                //     var tokenParts = headerValue.ToString().Split(' ');
                //     if (tokenParts.Length > 1)
                //     {
                //         var token = (JwtSecurityToken) handler.ReadToken(tokenParts[1]);
                //         if (token != null)
                //         {
                //             Logger.Info(token.Claims.First(claim => claim.Type == JwtRegisteredClaimNames.NameId).Value);
                //         }
                //     }
                //     else
                //     {
                //         Logger.Info("Invalid token: " + headerValue);
                //     }
                // }
                
                var username = User.Claims.First(claim => claim.Type == ClaimTypes.NameIdentifier).Value;
                Logger.Info(username);
            }
            catch (Exception e)
            {
                Logger.Info(e);
            }
            return "fireddddd";
        }

        [HttpGet("[action]")]
        public string Test2()
        {
            return "fireddddd";
        }
    }
}
