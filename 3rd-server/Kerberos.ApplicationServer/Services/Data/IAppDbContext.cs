using Kerberos.ApplicationServer.Domain;
using Microsoft.EntityFrameworkCore;

namespace Kerberos.ApplicationServer.Services.Data
{
    public interface IAppDbContext
    {
        DbSet<Realm> Realms { get; }

        DbSet<UserProfile> UserProfiles { get; }

        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    }
}
