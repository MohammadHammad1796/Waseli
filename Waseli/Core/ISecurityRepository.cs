using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace Waseli.Core
{
    public interface ISecurityRepository
    {
        Task<IdentityUser> GetUserByEmailAsync(string email);
        Task<IdentityUser> GetUserByIdAsync(string id);
        Task<bool> CheckPasswordAsync(IdentityUser user, string password);
        Task<object> GenerateToken(IdentityUser user);
        Task<IdentityResult> CreateUser(IdentityUser user, string password);
        Task<IdentityResult> ConfirmEmail(IdentityUser user, string code);
        Task<string> GenerateEmailConfirmationCode(IdentityUser user);
        bool IsLoginRequireConfirmedAccount();
    }
}
