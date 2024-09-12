using Kerberos.ApplicationServer.Application.Processing;
using Kerberos.ApplicationServer.Application.Processing.Implementations;

namespace Kerberos.ApplicationServer.Application
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddApplication(this IServiceCollection services)
        {
            services.AddTransient<IUserProfileProcessingService, UserProfileProcessingService>();

            return services;
        }
    }
}
