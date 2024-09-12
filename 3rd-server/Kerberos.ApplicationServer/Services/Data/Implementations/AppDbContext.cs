using Kerberos.ApplicationServer.Domain;
using Microsoft.EntityFrameworkCore;

namespace Kerberos.ApplicationServer.Services.Data.Implementations
{
    public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options), IAppDbContext
    {
        public DbSet<Realm> Realms => Set<Realm>();

        public DbSet<UserProfile> UserProfiles => Set<UserProfile>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
        }
    }
}
