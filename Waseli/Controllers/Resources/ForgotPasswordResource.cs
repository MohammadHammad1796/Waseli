using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class ForgotPasswordResource
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}