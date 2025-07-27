using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.DTOs;
using SecureAuth.Services;
using System.Security.Claims;

namespace SecureAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user and return JWT token
        /// </summary>
        /// <param name="loginRequest">Login credentials</param>
        /// <returns>Authentication response with token and user information</returns>
        [HttpPost("login")]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 200)]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 400)]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 401)]
        public async Task<ActionResult<ApiResponseDto<AuthResponseDto>>> Login([FromBody] LoginRequestDto loginRequest)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(new ApiResponseDto<AuthResponseDto>
                {
                    Success = false,
                    Message = "Validation failed",
                    Errors = errors
                });
            }

            var result = await _authService.LoginAsync(loginRequest);
            
            if (!result.Success)
            {
                return Unauthorized(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        /// <param name="registerRequest">Registration information</param>
        /// <returns>Authentication response with token and user information</returns>
        [HttpPost("register")]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 200)]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 400)]
        [ProducesResponseType(typeof(ApiResponseDto<AuthResponseDto>), 409)]
        public async Task<ActionResult<ApiResponseDto<AuthResponseDto>>> Register([FromBody] RegisterRequestDto registerRequest)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(new ApiResponseDto<AuthResponseDto>
                {
                    Success = false,
                    Message = "Validation failed",
                    Errors = errors
                });
            }

            var result = await _authService.RegisterAsync(registerRequest);
            
            if (!result.Success)
            {
                if (result.Errors.Contains("Email already registered"))
                {
                    return Conflict(result);
                }
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Get current user profile
        /// </summary>
        /// <returns>User profile information</returns>
        [HttpGet("profile")]
        [Authorize]
        [ProducesResponseType(typeof(ApiResponseDto<UserDto>), 200)]
        [ProducesResponseType(typeof(ApiResponseDto<UserDto>), 401)]
        [ProducesResponseType(typeof(ApiResponseDto<UserDto>), 404)]
        public async Task<ActionResult<ApiResponseDto<UserDto>>> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ApiResponseDto<UserDto>
                {
                    Success = false,
                    Message = "Invalid token",
                    Errors = new List<string> { "User ID not found in token" }
                });
            }

            var result = await _authService.GetUserProfileAsync(userId);
            
            if (!result.Success)
            {
                return NotFound(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Logout current user
        /// </summary>
        /// <returns>Logout confirmation</returns>
        [HttpPost("logout")]
        [Authorize]
        [ProducesResponseType(typeof(ApiResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ApiResponseDto<bool>), 401)]
        public async Task<ActionResult<ApiResponseDto<bool>>> Logout()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ApiResponseDto<bool>
                {
                    Success = false,
                    Message = "Invalid token",
                    Errors = new List<string> { "User ID not found in token" }
                });
            }

            var result = await _authService.LogoutAsync(userId);
            return Ok(result);
        }

        /// <summary>
        /// Validate current token
        /// </summary>
        /// <returns>Token validation result</returns>
        [HttpGet("validate")]
        [Authorize]
        [ProducesResponseType(typeof(ApiResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ApiResponseDto<bool>), 401)]
        public ActionResult<ApiResponseDto<bool>> ValidateToken()
        {
            return Ok(new ApiResponseDto<bool>
            {
                Success = true,
                Message = "Token is valid",
                Data = true
            });
        }
    }
}
