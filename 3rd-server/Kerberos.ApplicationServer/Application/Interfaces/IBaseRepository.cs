namespace Kerberos.ApplicationServer.Application.Interfaces
{
    public interface IBaseRepository<T>
        where T : class
    {
        IQueryable<T> Entities { get; }

        Task<T> AddAsync(T entity);

        Task UpdateAsync(T entity);

        Task DeleteAsync(T entity);
    }
}
