using Comp375BackEnd.Data;
using Comp375BackEnd.Models;
using Comp375BackEnd.Models.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Comp375BackEnd.Controllers.Auth
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly MyContext _context;
        private readonly IPasswordHasher<UserModel> _passwordHasher;

        public AuthController(IConfiguration configuration, MyContext context, IPasswordHasher<UserModel> passwordHasher)
        {
            _configuration = configuration;
            _context = context;
            _passwordHasher = passwordHasher;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var user = _context.User.FirstOrDefault(u => u.Username == request.Username);
            if (user == null)
                return Unauthorized("Invalid credentials");

            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Failed)
                return Unauthorized("Invalid credentials");

            var roleName = _context.Role.FirstOrDefault(r => r.RoleId == user.RoleId)?.Name ?? "Guest";

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, roleName),
                new Claim("UserId", user.UserId.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                user = new { user.UserId, user.Username, Role = roleName }
            });
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequest model)
        {
            if (_context.User.Any(u => u.Username == model.Username))
                return BadRequest("Username already exists");

            var role = _context.Role.FirstOrDefault(r => r.Name == model.Role);
            if (role == null)
                return BadRequest("Invalid role");

            var user = new UserModel
            {
                Username = model.Username,
                PasswordHash = _passwordHasher.HashPassword(null, model.Password),
                RoleId = role.RoleId
            };

            _context.User.Add(user);
            _context.SaveChanges();

            return Ok("User registered successfully");
        }
    }
}
