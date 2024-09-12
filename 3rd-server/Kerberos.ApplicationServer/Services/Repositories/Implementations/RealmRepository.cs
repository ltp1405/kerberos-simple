using Kerberos.ApplicationServer.Domain;
using Kerberos.ApplicationServer.Services.Data;

namespace Kerberos.ApplicationServer.Services.Repositories.Implementations
{
    public class RealmRepository(IAppDbContext context) : IRealmRepository
    {
        private readonly IAppDbContext _context = context;
        public IQueryable<Realm> Entities => _context.Realms;

        public Task<Realm> AddAsync(Realm entity)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(Realm entity)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(Realm entity)
        {
            throw new NotImplementedException();
        }
    }
}
