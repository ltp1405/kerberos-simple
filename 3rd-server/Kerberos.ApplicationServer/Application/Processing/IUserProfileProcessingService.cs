using Kerberos.ApplicationServer.Application.Dtos;

namespace Kerberos.ApplicationServer.Application.Processing
{
    public interface IUserProfileProcessingService
    {
        Task<UserProfileDto> GetUserProfileAsync(string userId);
    }
}