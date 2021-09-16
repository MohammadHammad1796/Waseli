using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace Waseli.Core
{
    public interface ISecurityService
    {
        Task<IdentityUser> GetUserByEmailAsync(string email);
        Task<IdentityUser> GetUserByIdAsync(string id);
        Task<bool> CheckPasswordAsync(IdentityUser user, string password);
        Task<object> GenerateToken(IdentityUser user);
        Task<IdentityResult> CreateUser(IdentityUser user, string password);
        Task<IdentityResult> ConfirmEmail(IdentityUser user, string code);
        Task<IdentityResult> ConfirmEmailChange(IdentityUser user, string email, string code);
        Task<string> GenerateEmailConfirmationCode(IdentityUser user);
        Task<string> GenerateChangeEmailConfirmationCode(IdentityUser user, string email);
        bool IsLoginRequireConfirmedAccount();
        Task<IdentityResult> SetUserNameAsync(IdentityUser user, string email);
        Task<bool> IsEmailConfirmedAsync(IdentityUser user);
        Task<string> GeneratePasswordResetCodeAsync(IdentityUser user);
        Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string code, string password);
    }
}
