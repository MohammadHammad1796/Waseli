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
        private readonly ISecurityService _securityService;
        //private readonly ILogger<RegisterResource> _logger;
        private readonly IEmailSender _emailSender;

        public AccountsController(ISecurityService securityService, IEmailSender emailSender)
        {
            _securityService = securityService;
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

            var result = await _securityService.CreateUser(user, registerResource.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(String.Empty, error.Description);

                return BadRequest(ModelState);
            }

            /*_logger.LogInformation("User created a new account with password.");*/

            var code = await _securityService.GenerateEmailConfirmationCode(user);

            var callbackUrl = Url.Action(
                "confirmEmail", "Accounts",
                //pageHandler: null,
                values: new ConfirmEmailResource(user.Id, code),
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(registerResource.Email, "Confirm your email",
               $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            if (_securityService.IsLoginRequireConfirmedAccount())
                return Ok("We send confirmation message to your email.");
            else
                return await Login(new LoginResource { Email = registerResource.Email, Password = registerResource.Password });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginResource loginResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByEmailAsync(loginResource.Email);

            if (user == null)
                return NotFound();

            if (_securityService.IsLoginRequireConfirmedAccount())
                if (!user.EmailConfirmed)
                    return BadRequest("You must confirm your account.");

            if (!await _securityService.CheckPasswordAsync(user, loginResource.Password))
                return BadRequest();

            return Ok(await _securityService.GenerateToken(user));

        }

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromHeader] ConfirmEmailResource confirmEmailResource)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var user = await _securityService.GetUserByIdAsync(confirmEmailResource.UserId);
            if (user == null)
                return NotFound();

            var result = await _securityService.ConfirmEmail(user, confirmEmailResource.Code);

            return result.Succeeded ? Ok(new { tokenInfo = await _securityService.GenerateToken(user), message = "Thank you for confirming your email." })
                : BadRequest("Error confirming your email.");

        }

        [HttpPost("changeEmail")]
        public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailResource changeEmailResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _securityService.GetUserByIdAsync(changeEmailResource.UserId);
            if (user == null)
                return NotFound($"Unable to load user with ID '{changeEmailResource.UserId}'.");

            if (user.Email.Equals(changeEmailResource.Email))
                return BadRequest("This is same email you use.");

            var userUsedEmail = await _securityService.GetUserByEmailAsync(changeEmailResource.Email);
            if (userUsedEmail != null)
                return BadRequest("This email is used.");

            //if (user == await _securityRepository.GetUserByEmailAsync(changeEmailResource.Email))
            //    return BadRequest("This email is used.");

            var code = await _securityService.GenerateChangeEmailConfirmationCode(user, changeEmailResource.Email);

            var callbackUrl = Url.Action(
                "ChangeEmailConfirmation", "Accounts",
                // pageHandler: null,
                values: new ConfirmEmailChangeResource(user.Id, changeEmailResource.Email, code),
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(changeEmailResource.Email, "Confirm your new email",
                $"Please confirm your new email by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            return Ok("Email Sent.");
        }

        [HttpGet("changeEmailConfirmation")]
        public async Task<IActionResult> ChangeEmailConfirmation(
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
            return Ok("Thank you for confirming your email change.");
        }

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
                values: new { code = code},
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(
                    forgotPasswordResource.Email,
                    "Reset Password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            return Ok("Email sent.");
        }

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

            return Ok("password reseted successfully.");
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
