using System.ComponentModel.DataAnnotations;

namespace Waseli.Controllers.Resources
{
    public class SetPhoneNumberResource
    {
        [Phone]
        [Display(Name = "Phone number")]
        public string PhoneNumber { get; set; }
    }
}