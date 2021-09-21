using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Waseli.Core.Models;

namespace Waseli.Core
{
    public interface ISecurityService
    {
        Task<User> GetUserByEmailAsync(string email);
        Task<User> GetUserByIdAsync(string id);
        Task<bool> CheckPasswordAsync(User user, string password);
        Task<object> GenerateToken(User user);
        Task Logout(User user, bool fromAllDevices, string token);
        Task<IdentityResult> CreateUser(User user, string password);
        Task<IdentityResult> ConfirmEmail(User user, string code);
        Task<IdentityResult> ConfirmEmailChange(User user, string email, string code);
        Task<string> GenerateEmailConfirmationCode(User user);
        Task<string> GenerateChangeEmailConfirmationCode(User user, string email);
        bool IsLoginRequireConfirmedAccount();
        Task<IdentityResult> SetUserNameAsync(User user, string email);
        Task<bool> IsEmailConfirmedAsync(User user);
        Task<string> GeneratePasswordResetCodeAsync(User user);
        Task<IdentityResult> ResetPasswordAsync(User user, string code, string password);
        Task<string> GetUserIdAsync(User user);
        Task<bool> IsLockedOutAsync(User user);
        Task<bool> HasPasswordAsync(User user);
        Task<IdentityResult> ChangePasswordAsync(User user, string oldPassword, string newPassword);
        Task<IdentityResult> AddPasswordAsync(User user, string newPassword);
        Task<string> GetPhoneNumberAsync(User user);
        Task<IdentityResult> SetPhoneNumberAsync(User user, string phoneNumber);
        Task<IdentityResult> DeleteAccountAsync(User user);
    }
}
