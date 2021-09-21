using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Waseli.Core.Models;

namespace Waseli.Persistence
{
    public class WaseliDbContext : IdentityDbContext
    {
        public WaseliDbContext(DbContextOptions<WaseliDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> AspNetUsers { get; set; }
        public DbSet<ValidToken> ValidTokens { get; set; }
        public DbSet<InvalidToken> InvalidTokens { get; set; }
    }
}
