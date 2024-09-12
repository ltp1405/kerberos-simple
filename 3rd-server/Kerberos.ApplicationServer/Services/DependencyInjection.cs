using Kerberos.ApplicationServer.Application.Interfaces;
using Kerberos.ApplicationServer.Domain;
using Kerberos.ApplicationServer.Services.Data;
using Kerberos.ApplicationServer.Services.Data.Implementations;
using Kerberos.ApplicationServer.Services.Repositories;
using Kerberos.ApplicationServer.Services.Repositories.Implementations;
using Microsoft.EntityFrameworkCore;

namespace Kerberos.ApplicationServer.Services
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddServices(
            this IServiceCollection services,
            IConfiguration configuration
        )
        {
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
            });

            services.AddScoped<IAppDbContext>(serviceProvider =>
                serviceProvider.GetRequiredService<AppDbContext>()
            );

            services.AddScoped<IUserProfileRepository, UserRepository>();

            services.AddScoped<IBaseRepository<UserProfile>>(serviceProvider =>
                serviceProvider.GetRequiredService<IUserProfileRepository>()
            );

            services.AddScoped<IRealmRepository, RealmRepository>();

            services.AddScoped<IBaseRepository<Realm>>(serviceProvider =>
                serviceProvider.GetRequiredService<IRealmRepository>()
            );

            return services;
        }
    }
}
