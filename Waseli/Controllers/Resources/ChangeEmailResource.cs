using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class ChangeEmailResource
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}