using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Waseli.Persistence
{
    public class WaseliDbContext : IdentityDbContext
    {
        public WaseliDbContext(DbContextOptions<WaseliDbContext> options)
            : base(options)
        {
        }
    }
}
