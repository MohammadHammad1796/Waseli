using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class SetPasswordResource
    {
        public SetPasswordResource()
        {
        }

        public SetPasswordResource(string newPassword, string confirmPassword)
        {
            NewPassword = newPassword;
            ConfirmPassword = confirmPassword;
        }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}