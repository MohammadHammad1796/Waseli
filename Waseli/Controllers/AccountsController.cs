using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Waseli.Controllers.Resources;
using Waseli.Core;
using Waseli.Core.Models;

namespace Waseli.Controllers
{
    [Route("api/accounts")]
    public class AccountsController : Controller
    {
        private readonly ISecurityService _securityService;
        //private readonly ILogger<RegisterResource> _logger;
        private readonly IEmailSender _emailSender;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly User _user;

        public AccountsController(ISecurityService securityService, IEmailSender emailSender, IHttpContextAccessor httpContextAccessor)
        {
            _securityService = securityService;
            _emailSender = emailSender;
            _httpContextAccessor = httpContextAccessor;
            if (_httpContextAccessor.HttpContext?.User.Identity?.Name != null)
            {
                var userName = _httpContextAccessor.HttpContext.User.Identity.Name;
                _user = _securityService.GetUserByEmailAsync(userName).Result;
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterResource registerResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            //registerModel.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            var user = new User
            { UserName = registerResource.Email, Email = registerResource.Email, EmailConfirmed = false };

            var result = await _securityService.CreateUser(user, registerResource.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(String.Empty, error.Description);

                return BadRequest(ModelState);
            }

            /*_logger.LogInformation("User created a new account with password.");*/
            var userId = await _securityService.GetUserIdAsync(user);
            var code = await _securityService.GenerateEmailConfirmationCode(user);

            var callbackUrl = Url.Action(
                "confirmEmail", "Accounts",
                //pageHandler: null,
                values: new ConfirmEmailResource(userId, code),
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(registerResource.Email, "Confirm your email",
               $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            if (_securityService.IsLoginRequireConfirmedAccount())
                return Ok("We send confirmation message to your email.");
            else
                return await Login(new LoginResource { Email = registerResource.Email, Password = registerResource.Password });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginResource loginResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByEmailAsync(loginResource.Email);

            if (user == null)
                return NotFound();

            if (_securityService.IsLoginRequireConfirmedAccount())
                if (!await _securityService.IsEmailConfirmedAsync(user))
                    return BadRequest("You must confirm your account.");

            if (await _securityService.IsLockedOutAsync(user))
                return BadRequest("User account locked out");

            if (!await _securityService.CheckPasswordAsync(user, loginResource.Password))
                return BadRequest("Username or password incorrect");

            return Ok(await _securityService.GenerateToken(user));

        }

        [AllowAnonymous]
        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromHeader] ConfirmEmailResource confirmEmailResource)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var user = await _securityService.GetUserByIdAsync(confirmEmailResource.UserId);
            if (user == null)
                return NotFound($"Unable to load user with ID '{confirmEmailResource.UserId}'.");

            var result = await _securityService.ConfirmEmail(user, confirmEmailResource.Code);

            return result.Succeeded ?
                Ok(new
                {
                    message = "Thank you for confirming your email."
                })
                : BadRequest("Error confirming your email.");

        }

        [AllowAnonymous]
        [HttpGet("confirmEmailChange")]
        public async Task<IActionResult> ConfirmEmailChange(
            [FromHeader] ConfirmEmailChangeResource confirmEmailChangeResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByIdAsync(confirmEmailChangeResource.UserId);
            if (user == null)
                return NotFound($"Unable to load user with ID '{confirmEmailChangeResource.UserId}'.");

            var result = await _securityService.ConfirmEmailChange(user, confirmEmailChangeResource.Email, confirmEmailChangeResource.Code);
            if (!result.Succeeded)
                return BadRequest("Error changing email.");

            // In our UI email and user name are one and the same, so when we update the email
            // we need to update the user name.
            var setUserNameResult = await _securityService.SetUserNameAsync(user, confirmEmailChangeResource.Email);
            if (!setUserNameResult.Succeeded)
                return BadRequest("Error changing user name.");

            //await _signInManager.RefreshSignInAsync(user);
            return Ok(new
            {
                tokenInfo = await _securityService.GenerateToken(user),
                message = "Thank you for confirming your email change."
            });
        }

        [AllowAnonymous]
        [HttpPost("forgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordResource forgotPasswordResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByEmailAsync(forgotPasswordResource.Email);
            if (user == null)
                return NotFound();

            if (!await _securityService.IsEmailConfirmedAsync(user))
                return BadRequest("Sorry, your email is not confirmed so we can not send an email to change password");

            var code = await _securityService.GeneratePasswordResetCodeAsync(user);
            var callbackUrl = Url.Action(
                "ResetPassword", "Accounts",
                values: new { Code = code },
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(
                    forgotPasswordResource.Email,
                    "Reset Password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            return Ok("Email sent.");
        }

        [AllowAnonymous]
        [HttpGet("resetPassword")]
        public async Task<IActionResult> ResetPassword([FromHeader] ResetPasswordResource resetPasswordResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByEmailAsync(resetPasswordResource.Email);
            if (user == null)
                return NotFound();

            var result = await _securityService.ResetPasswordAsync(user, resetPasswordResource.Code,
                resetPasswordResource.Password);

            if (!result.Succeeded)
                return BadRequest("Error reset password.");

            return Ok(new
            {
                tokenInfo = await _securityService.GenerateToken(user),
                message = "password reset successfully."
            });
        }

        [Authorize]
        [HttpGet("logout")]
        public async Task<IActionResult> Logout([FromQuery] bool fromAllDevices = false)
        {
            var token = _httpContextAccessor.HttpContext.Request.Headers["Authorization"].ToString();
            await _securityService.Logout(_user, fromAllDevices, token.Split(' ')[1]);
            //_logger.LogInformation("User ({0}) logged out", _user.UserName);
            return Ok("Logout successfully");
        }

        [Authorize]
        [HttpGet("testAuthentication")]
        public IActionResult TestAuthentication()
        {
            return Ok(new { _user, message = "Success Authentication" });
        }

        [Authorize]
        [HttpGet("testUnAuthentication")]
        public IActionResult TestUnAuthentication()
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
