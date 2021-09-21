using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Waseli.Core.Models
{
    [Table("AspNetUsers")]
    public class User : IdentityUser
    {
        public virtual ICollection<ValidToken> ValidTokens { get; set; }
        public virtual ICollection<InvalidToken> InvalidTokens { get; set; }

        public User()
        {
            ValidTokens = new List<ValidToken>();
            InvalidTokens = new List<InvalidToken>();
        }
    }
}