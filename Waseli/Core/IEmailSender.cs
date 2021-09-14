using System.Threading.Tasks;

namespace Waseli.Core
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}