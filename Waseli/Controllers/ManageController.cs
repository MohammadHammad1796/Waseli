using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Waseli.Controllers.Resources;
using Waseli.Core;
using Waseli.Core.Models;

namespace Waseli.Controllers
{
    [Route("api/accounts/manage")]
    public class ManageController : Controller
    {
        private readonly ISecurityService _securityService;
        //private readonly ILogger<RegisterResource> _logger;
        private readonly IEmailSender _emailSender;
        private readonly User _user;

        public ManageController(ISecurityService securityService, IEmailSender emailSender, IHttpContextAccessor httpContextAccessor)
        {
            _securityService = securityService;
            _emailSender = emailSender;
            var httpContextAccessor1 = httpContextAccessor;
            if (httpContextAccessor1.HttpContext?.User.Identity?.Name != null)
            {
                var userName = httpContextAccessor1.HttpContext.User.Identity.Name;
                _user = _securityService.GetUserByEmailAsync(userName).Result;
            }
        }

        [Authorize]
        [HttpPost("changePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordResource changePasswordResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!await _securityService.HasPasswordAsync(_user))
                return await SetPassword(new SetPasswordResource(changePasswordResource.NewPassword, changePasswordResource.ConfirmPassword));

            var changePasswordResult = await _securityService.ChangePasswordAsync(_user,
                changePasswordResource.OldPassword, changePasswordResource.NewPassword);

            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return BadRequest(ModelState);
            }

            //_logger.LogInformation("User ({0}) changed their password successfully.", _user.UserName);

            return Ok("Your password has been changed.");
        }

        [Authorize]
        [HttpPost("setPassword")]
        public async Task<IActionResult> SetPassword([FromBody] SetPasswordResource setPasswordResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (await _securityService.HasPasswordAsync(_user))
                return BadRequest("You must change old password");

            var addPasswordResult = await _securityService.AddPasswordAsync(_user, setPasswordResource.NewPassword);
            if (!addPasswordResult.Succeeded)
            {
                foreach (var error in addPasswordResult.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return BadRequest(ModelState);
            }

            return Ok("Your password has been set.");
        }

        [Authorize]
        [HttpPost("setPhoneNumber")]
        public async Task<IActionResult> SetPhoneNumber([FromBody] SetPhoneNumberResource setPhoneNumberResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var oldPhoneNumber = await _securityService.GetPhoneNumberAsync(_user);
            if (setPhoneNumberResource.PhoneNumber == oldPhoneNumber)
                return BadRequest("This is same number you use");

            var result = await _securityService.SetPhoneNumberAsync(_user, setPhoneNumberResource.PhoneNumber);
            if (!result.Succeeded)
                return BadRequest("Unexpected error when trying to set phone number.");

            return Ok("Your phone number has been updated");

        }

        [Authorize]
        [HttpPost("deleteAccount")]
        public async Task<IActionResult> DeleteAccount([FromBody] DeleteAccountResource deleteAccountResource)
        {
            if (await _securityService.HasPasswordAsync(_user))
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                if (!await _securityService.CheckPasswordAsync(_user, deleteAccountResource.Password))
                {
                    ModelState.AddModelError(String.Empty, "Incorrect password");
                    return BadRequest(ModelState);
                }
            }

            var result = await _securityService.DeleteAccountAsync(_user);
            if (!result.Succeeded)
                return BadRequest("Unexpected error occurred deleting user with ID " + _user.Id);

            //_logger.LogInformation("User with ID '{UserId}' deleted themselves.", _user.Id);
            return Ok("Account deleted successfully");
        }

        [Authorize]
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
                "ConfirmEmailChange", "Accounts",
                // pageHandler: null,
                values: new ConfirmEmailChangeResource(user.Id, changeEmailResource.Email, code),
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(changeEmailResource.Email, "Confirm your new email",
                $"Please confirm your new email by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            return Ok("Email Sent.");
        }
    }
}
