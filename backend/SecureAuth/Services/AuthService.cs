using MongoDB.Driver;
using SecureAuth.DTOs;
using SecureAuth.Models;
using SecureAuth.Data;
using BCrypt.Net;

namespace SecureAuth.Services
{
    public interface IAuthService
    {
        Task<ApiResponseDto<AuthResponseDto>> LoginAsync(LoginRequestDto loginRequest);
        Task<ApiResponseDto<AuthResponseDto>> RegisterAsync(RegisterRequestDto registerRequest);
        Task<ApiResponseDto<UserDto>> GetUserProfileAsync(string userId);
        Task<ApiResponseDto<bool>> LogoutAsync(string userId);
    }

    public class AuthService : IAuthService
    {
        private readonly IMongoDbContext _mongoContext;
        private readonly IJwtService _jwtService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IMongoDbContext mongoContext,
            IJwtService jwtService,
            ILogger<AuthService> logger)
        {
            _mongoContext = mongoContext;
            _jwtService = jwtService;
            _logger = logger;
        }

        public async Task<ApiResponseDto<AuthResponseDto>> LoginAsync(LoginRequestDto loginRequest)
        {
            try
            {
                // Find user by email
                var user = await _mongoContext.Users
                    .Find(u => u.Email == loginRequest.Email && u.IsActive)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    _logger.LogWarning("Login attempt with non-existent email: {Email}", loginRequest.Email);
                    return new ApiResponseDto<AuthResponseDto>
                    {
                        Success = false,
                        Message = "Invalid email or password.",
                        Errors = new List<string> { "Authentication failed" }
                    };
                }

                // Verify password
                if (!BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.PasswordHash))
                {
                    _logger.LogWarning("Failed login attempt for user {Email}", loginRequest.Email);
                    return new ApiResponseDto<AuthResponseDto>
                    {
                        Success = false,
                        Message = "Invalid email or password.",
                        Errors = new List<string> { "Authentication failed" }
                    };
                }

                // Update last login time
                user.LastLoginAt = DateTime.UtcNow;
                await _mongoContext.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

                var token = _jwtService.GenerateToken(user);
                var userDto = MapToUserDto(user);

                _logger.LogInformation("User {Email} logged in successfully", user.Email);

                return new ApiResponseDto<AuthResponseDto>
                {
                    Success = true,
                    Message = "Login successful",
                    Data = new AuthResponseDto
                    {
                        Token = token,
                        User = userDto,
                        Expires = DateTime.UtcNow.AddHours(24)
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during login for {Email}", loginRequest.Email);
                return new ApiResponseDto<AuthResponseDto>
                {
                    Success = false,
                    Message = "An error occurred during login",
                    Errors = new List<string> { "Internal server error" }
                };
            }
        }

        public async Task<ApiResponseDto<AuthResponseDto>> RegisterAsync(RegisterRequestDto registerRequest)
        {
            try
            {
                // Check if user already exists
                var existingUser = await _mongoContext.Users
                    .Find(u => u.Email == registerRequest.Email)
                    .FirstOrDefaultAsync();

                if (existingUser != null)
                {
                    return new ApiResponseDto<AuthResponseDto>
                    {
                        Success = false,
                        Message = "User with this email already exists",
                        Errors = new List<string> { "Email already registered" }
                    };
                }

                // Hash password
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(registerRequest.Password, BCrypt.Net.BCrypt.GenerateSalt(12));

                // Create new user
                var user = new ApplicationUser
                {
                    Name = registerRequest.Name,
                    Email = registerRequest.Email,
                    PasswordHash = passwordHash,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                // Insert user into database
                await _mongoContext.Users.InsertOneAsync(user);

                var token = _jwtService.GenerateToken(user);
                var userDto = MapToUserDto(user);

                _logger.LogInformation("User {Email} registered successfully", user.Email);

                return new ApiResponseDto<AuthResponseDto>
                {
                    Success = true,
                    Message = "Registration successful",
                    Data = new AuthResponseDto
                    {
                        Token = token,
                        User = userDto,
                        Expires = DateTime.UtcNow.AddHours(24)
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during registration for {Email}", registerRequest.Email);
                return new ApiResponseDto<AuthResponseDto>
                {
                    Success = false,
                    Message = "An error occurred during registration",
                    Errors = new List<string> { "Internal server error" }
                };
            }
        }

        public async Task<ApiResponseDto<UserDto>> GetUserProfileAsync(string userId)
        {
            try
            {
                var user = await _mongoContext.Users
                    .Find(u => u.Id == userId && u.IsActive)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    return new ApiResponseDto<UserDto>
                    {
                        Success = false,
                        Message = "User not found",
                        Errors = new List<string> { "User does not exist" }
                    };
                }

                var userDto = MapToUserDto(user);

                return new ApiResponseDto<UserDto>
                {
                    Success = true,
                    Message = "User profile retrieved successfully",
                    Data = userDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while retrieving user profile for {UserId}", userId);
                return new ApiResponseDto<UserDto>
                {
                    Success = false,
                    Message = "An error occurred while retrieving user profile",
                    Errors = new List<string> { "Internal server error" }
                };
            }
        }

        public Task<ApiResponseDto<bool>> LogoutAsync(string userId)
        {
            try
            {
                // In a more complex implementation, you might want to blacklist the token
                // For now, we'll just log the logout event
                _logger.LogInformation("User {UserId} logged out", userId);

                return Task.FromResult(new ApiResponseDto<bool>
                {
                    Success = true,
                    Message = "Logout successful",
                    Data = true
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during logout for {UserId}", userId);
                return Task.FromResult(new ApiResponseDto<bool>
                {
                    Success = false,
                    Message = "An error occurred during logout",
                    Errors = new List<string> { "Internal server error" }
                });
            }
        }

        private static UserDto MapToUserDto(ApplicationUser user)
        {
            return new UserDto
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt
            };
        }
    }
}
