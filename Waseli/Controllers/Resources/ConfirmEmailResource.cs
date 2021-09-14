using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class ConfirmEmailResource
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        public string Code { get; set; }

        public ConfirmEmailResource(string userId, string code)
        {
            UserId = userId;
            Code = code;
        }

        public ConfirmEmailResource()
        {
        }
    }
}