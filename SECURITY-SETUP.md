# SecureAuth System Setup

## Security Configuration

This project uses secure configuration management to protect sensitive data like database connection strings and JWT secret keys.

### Development Setup

1. **Copy the template file:**
   ```bash
   cp backend/SecureAuth/appsettings.Development.json.template backend/SecureAuth/appsettings.Development.json
   ```

2. **Update the configuration:**
   Edit `backend/SecureAuth/appsettings.Development.json` and replace:
   - `YOUR_MONGODB_CONNECTION_STRING_HERE` with your actual MongoDB connection string
   - `YOUR_JWT_SECRET_KEY_HERE_AT_LEAST_32_CHARACTERS` with a secure JWT secret key

3. **Never commit sensitive files:**
   - `appsettings.Development.json` is in `.gitignore` and should never be committed
   - Only the template file should be committed to the repository

### Production Setup

For production deployment, use environment variables:

```bash
export ConnectionStrings__ConnectionString="your-production-mongodb-connection"
export Jwt__SecretKey="your-production-jwt-secret"
```

Or use your cloud provider's secret management:
- Azure: Azure Key Vault
- AWS: AWS Secrets Manager
- Google Cloud: Secret Manager

### Environment Variables

The application supports these environment variables:

- `ConnectionStrings__ConnectionString` - MongoDB connection string
- `ConnectionStrings__DataBase` - Database name (default: securedb)
- `ConnectionStrings__Collection` - Collection name (default: users)
- `Jwt__SecretKey` - JWT signing key
- `Jwt__Issuer` - JWT issuer (default: SecureAuth)
- `Jwt__Audience` - JWT audience (default: SecureAuthUsers)
- `Jwt__ExpirationHours` - Token expiration time (default: 24)

### Security Best Practices

1. **Never commit secrets to Git**
2. **Use different keys for different environments**
3. **Rotate secrets regularly**
4. **Use proper secret management in production**
5. **Limit access to production secrets**

## MongoDB Connection Issues

If you encounter MongoDB connection issues:

1. **Check IP Whitelist:** Ensure your IP is whitelisted in MongoDB Atlas
2. **Verify Credentials:** Double-check username and password
3. **Network Access:** Check firewall and network settings
4. **Connection String Format:** Ensure proper URL encoding

## Getting Started

1. Set up your development configuration (see above)
2. Run the backend: `dotnet run` from `backend/SecureAuth/`
3. Run the frontend: `ng serve` from `frontend/secureAuth/`

## Troubleshooting

### MongoDB Connection Timeout
- Check MongoDB Atlas network access settings
- Verify your IP is whitelisted
- Ensure credentials are correct

### CORS Issues
- Check that frontend URL is in CORS allowed origins
- Verify both HTTP and HTTPS variants if needed
