using System;
using System.ComponentModel.DataAnnotations;

namespace Waseli.Core.Models
{
    public class InvalidToken
    {
        [Required]
        public int Id { get; set; }
        [Required(AllowEmptyStrings = false)]
        public string Token { get; set; }
        [Required]
        public DateTime ExpirationTime { get; set; }
        [Required(AllowEmptyStrings = false)]
        public string UserId { get; set; }

        public User User { get; set; }
    }
}