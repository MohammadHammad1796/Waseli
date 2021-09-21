using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Waseli.Core;
using Waseli.Core.Models;

namespace Waseli.Persistence
{
    public class SecurityService : ISecurityService
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;

        private readonly WaseliDbContext _context;

        private readonly UserStore<User> _userStore;

        private readonly IMapper _mapper;
        /*private readonly RoleManager<IdentityRole> _roleManager;*/
        /*private readonly SignInManager<User> _signInManager;*/

        public SecurityService(UserManager<User> userManager, IConfiguration configuration, WaseliDbContext context, IMapper mapper /*, RoleManager<IdentityRole> roleManager*/ /*, SignInManager<User> signInManager*/)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
            _mapper = mapper;
            _userStore = new UserStore<User>(_context);
            /*_roleManager = roleManager;*/
            /*_signInManager = signInManager;*/
        }

        public void CreateRole()
        {
            //IdentityRole r = new IdentityRole();
            //r.
            //_roleManager.CreateAsync()
        }

        public async Task<User> GetUserByEmailAsync(string email)
        {
            return await _userManager.FindByNameAsync(email);
        }

        public async Task<User> GetUserByIdAsync(string id)
        {
            return await _userManager.FindByIdAsync(id);
        }

        public async Task<bool> CheckPasswordAsync(User user, string password)
        {
            return await _userManager.CheckPasswordAsync(user, password);
        }

        public async Task<bool> IsLockedOutAsync(User user)
        {
            return await _userManager.IsLockedOutAsync(user);
        }

        public async Task<object> GenerateToken(User user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("UserId", user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var userRole in userRoles)
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            user.ValidTokens.Add(new ValidToken { Token = jwt, ExpirationTime = token.ValidTo, UserId = user.Id });
            await _userManager.UpdateAsync(user);
            return new
            {
                token = jwt,
                expiration = token.ValidTo.AddHours(3)
            };
        }

        public async Task Logout(User user, bool fromAllDevices, string token)
        {
            var validTokens = _context.ValidTokens.Where(v => v.UserId == user.Id);

            if (!fromAllDevices)
            {
                var tokenToDelete = await validTokens.FirstAsync(v => v.Token == token);
                var invalidToken = _mapper.Map<InvalidToken>(tokenToDelete);
                await _context.InvalidTokens.AddAsync(_mapper.Map<InvalidToken>(tokenToDelete));
                _context.ValidTokens.Remove(tokenToDelete);
            }
            else
            {
                var tokensToDelete = await validTokens.ToListAsync();
                await _context.InvalidTokens.AddRangeAsync(_mapper.Map<List<InvalidToken>>(tokensToDelete));
                _context.ValidTokens.RemoveRange(tokensToDelete);
            }

            await _context.SaveChangesAsync();
        }

        public Task<IdentityResult> CreateUser(User user, string password)
        {
            return _userManager.CreateAsync(user, password);
        }

        public async Task<string> GenerateEmailConfirmationCode(User user)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            return code;
        }

        public async Task<IdentityResult> ConfirmEmail(User user, string code)
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return result;
        }

        public async Task<IdentityResult> ConfirmEmailChange(User user, string email, string code)
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ChangeEmailAsync(user, email, code);
            return result;
        }

        public async Task<IdentityResult> SetUserNameAsync(User user, string email)
        {
            var result = await _userManager.SetUserNameAsync(user, email);
            return result;
        }

        public bool IsLoginRequireConfirmedAccount()
        {
            return _userManager.Options.SignIn.RequireConfirmedAccount;
        }

        public async Task<string> GenerateChangeEmailConfirmationCode(User user, string email)
        {
            var code = await _userManager.GenerateChangeEmailTokenAsync(user, email);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            return code;
        }

        public async Task<bool> IsEmailConfirmedAsync(User user)
        {
            return await _userManager.IsEmailConfirmedAsync(user);
        }

        public async Task<string> GeneratePasswordResetCodeAsync(User user)
        {
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            return code;
        }

        public async Task<IdentityResult> ResetPasswordAsync(User user, string code, string password)
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            return await _userManager.ResetPasswordAsync(user, code, password);
        }

        public async Task<string> GetUserIdAsync(User user)
        {
            return await _userManager.GetUserIdAsync(user);
        }

        public async Task<bool> HasPasswordAsync(User user)
        {
            return await _userManager.HasPasswordAsync(user);
        }

        public async Task<IdentityResult> ChangePasswordAsync(User user, string oldPassword, string newPassword)
        {
            return await _userManager.ChangePasswordAsync(user, oldPassword, newPassword);
        }

        public async Task<IdentityResult> AddPasswordAsync(User user, string newPassword)
        {
            return await _userManager.AddPasswordAsync(user, newPassword);
        }

        public async Task<string> GetPhoneNumberAsync(User user)
        {
            return await _userManager.GetPhoneNumberAsync(user);
        }

        public async Task<IdentityResult> SetPhoneNumberAsync(User user, string phoneNumber)
        {
            return await _userManager.SetPhoneNumberAsync(user, phoneNumber);
        }

        public async Task<IdentityResult> DeleteAccountAsync(User user)
        {
            return await _userManager.DeleteAsync(user);
        }
    }
}