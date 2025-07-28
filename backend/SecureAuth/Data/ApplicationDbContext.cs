using MongoDB.Driver;
using SecureAuth.Models;

namespace SecureAuth.Data
{
    public interface IMongoDbContext
    {
        IMongoCollection<ApplicationUser> Users { get; }
    }

    public class MongoDbContext : IMongoDbContext
    {
        private readonly IMongoDatabase _database;

        public MongoDbContext(IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("ConnectionString");
            var databaseName = configuration.GetConnectionString("DataBase");

            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentException("MongoDB connection string is not configured.");

            if (string.IsNullOrEmpty(databaseName))
                throw new ArgumentException("MongoDB database name is not configured.");

            var client = new MongoClient(connectionString);
            _database = client.GetDatabase(databaseName);
        }

        public IMongoCollection<ApplicationUser> Users
        {
            get
            {
                var collectionName = "users"; // You can make this configurable too
                return _database.GetCollection<ApplicationUser>(collectionName);
            }
        }
    }
}
