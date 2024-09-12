using Kerberos.ApplicationServer.Application.Dtos;
using Kerberos.ApplicationServer.Application.Interfaces;
using Kerberos.ApplicationServer.Domain;

namespace Kerberos.ApplicationServer.Application.Processing.Implementations
{
    public class UserProfileProcessingService(
        IBaseRepository<UserProfile> userProfileRepository,
        IBaseRepository<Realm> realmRepository
    ) : IUserProfileProcessingService
    {
        private readonly IBaseRepository<UserProfile> _userProfileRepository =
            userProfileRepository;

        private readonly IBaseRepository<Realm> _realmRepository = realmRepository;

        public Task<UserProfileDto> GetUserProfileAsync(string userId)
        {
            throw new NotImplementedException();
        }
    }
}
