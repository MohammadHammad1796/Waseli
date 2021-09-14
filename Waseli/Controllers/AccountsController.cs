using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Waseli.Controllers.Resources;
using Waseli.Core;

namespace Waseli.Controllers
{
    [Route("api/accounts")]
    public class AccountsController : Controller
    {
        private readonly ISecurityRepository _securityRepository;
        //private readonly ILogger<RegisterResource> _logger;
        private readonly IEmailSender _emailSender;

        public AccountsController(ISecurityRepository securityRepository, IEmailSender emailSender)
        {
            _securityRepository = securityRepository;
            _emailSender = emailSender;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterResource registerResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            //registerModel.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            var user = new IdentityUser
            { UserName = registerResource.Email, Email = registerResource.Email, EmailConfirmed = false };

            var result = await _securityRepository.CreateUser(user, registerResource.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(String.Empty, error.Description);

                return BadRequest(ModelState);
            }

            /*_logger.LogInformation("User created a new account with password.");*/

            var code = await _securityRepository.GenerateEmailConfirmationCode(user);

            var callbackUrl = Url.Action(
                "confirmEmail", "Accounts",
                //pageHandler: null,
                values: new ConfirmEmailResource(user.Id, code),
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(registerResource.Email, "Confirm your email",
               $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            if (_securityRepository.IsLoginRequireConfirmedAccount())
                return Ok("We send confirmation message to your email.");
            else
                return await Login(new LoginResource { Email = registerResource.Email, Password = registerResource.Password });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginResource loginResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityRepository.GetUserByEmailAsync(loginResource.Email);

            if (user == null)
                return NotFound();

            if (!await _securityRepository.CheckPasswordAsync(user, loginResource.Password))
                return BadRequest();

            return Ok(await _securityRepository.GenerateToken(user));

        }

        [HttpGet("confirmemail")]
        public async Task<IActionResult> ConfirmEmail([FromHeader] ConfirmEmailResource confirmEmailResource)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var user = await _securityRepository.GetUserByIdAsync(confirmEmailResource.UserId);
            if (user == null)
                return NotFound();

            var result = await _securityRepository.ConfirmEmail(user, confirmEmailResource.Code);

            return result.Succeeded ? Ok(new { tokenInfo = await _securityRepository.GenerateToken(user), message = "Thank you for confirming your email." })
                : BadRequest("Error confirming your email.");

        }

        [Authorize]
        [HttpGet("testAuthentication")]
        public IActionResult TestAuthentication()
        {
            return Ok("Success Authentication");
        }

        [Authorize(Roles = "Administrator")]
        [HttpGet("testAuthorizationRole")]
        public IActionResult TestAuthorizationRole()
        {
            return Ok("Success Authorization Role");
        }

        [Authorize(Policy = "CanUpdate")]
        [HttpGet("testAuthorizationPolicy")]
        public IActionResult TestAuthorizationPolicy()
        {
            return Ok("Success Authorization Policy");
        }

        [Authorize(Roles = "Accountant")]
        [HttpGet("testUnAuthorizationRole")]
        public IActionResult TestUnAuthorizationRole()
        {
            return Ok("Success Authorization Role");
        }

        [Authorize(Policy = "CanRead")]
        [HttpGet("testUnAuthorizationPolicy")]
        public IActionResult TestUnAuthorizationPolicy()
        {
            return Ok("Success Authorization Policy");
        }
    }
}
