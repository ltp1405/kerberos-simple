using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.ApplicationServer.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Kerberos.ApplicationServer.Services.Data.Implementations.Configurations
{
    public class RealmConfiguration : IEntityTypeConfiguration<Realm>
    {
        public void Configure(EntityTypeBuilder<Realm> builder) { }
    }
}
