using Kerberos.ApplicationServer.Domain;
using Kerberos.ApplicationServer.Services.Data;
using Microsoft.EntityFrameworkCore;

namespace Kerberos.ApplicationServer.Services.Repositories.Implementations
{
    public class UserRepository(IAppDbContext context) : IUserProfileRepository
    {
        private readonly IAppDbContext _context = context;

        public IQueryable<UserProfile> Entities => _context.UserProfiles;

        public Task<UserProfile> AddAsync(UserProfile entity)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(UserProfile entity)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(UserProfile entity)
        {
            throw new NotImplementedException();
        }
    }
}
