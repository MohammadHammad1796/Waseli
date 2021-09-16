using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class ConfirmEmailChangeResource
    {
        public ConfirmEmailChangeResource(string userId, string email, string code)
        {
            UserId = userId;
            Email = email;
            Code = code;
        }

        public ConfirmEmailChangeResource()
        {
        }

        [Required]
        public string UserId { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Code { get; set; }
    }
}