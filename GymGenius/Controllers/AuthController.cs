using GymGenius.Helpers;
using GymGenius.Models.Identity;
using GymGenius.Models.Users;
using GymGenius.Services.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace GymGenius.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        private readonly IMailingRepository _mailingRepository;

        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt, IMailingRepository mailingRepository)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
            _mailingRepository = mailingRepository;
        }


        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return BadRequest( new AuthModel { Message = "Email is already registered!" });

            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return BadRequest (new AuthModel { Message = "Username is already registered!" });

            var Id = GenerateRandomID();

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };

            user.Id = Id;

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;

                foreach (var error in result.Errors)
                    errors += $"{error.Description},";

                return BadRequest(new AuthModel { Message = errors });
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);

            var refreshToken = GenerateRefreshToken();

            string url_ = "https://ocalhost:7031/Auth/ConfirmEmail?code=";
            var code = _userManager.GenerateEmailConfirmationTokenAsync(user);
            string UrlForReset = url_ + code;

            //var confirmMail = Url.Action(nameof(ConfirmEmail), "Auth", new { code, email = user.Email }, Request.Scheme);
            await _mailingRepository.SendingMail(user.Email, "Confirmation Email Link", $"<a href='{UrlForReset}'></a>");

            user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(user);

            return Ok(new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            });
        }


        //[Authorize(Roles = clsRoles.roleAdmin)]
        [HttpPost("registerwithRole")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model, string role)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return BadRequest( new AuthModel { Message = "Email is already registered!" });

            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return BadRequest(new AuthModel { Message = "Username is already registered!" });

            var Id = GenerateRandomID();

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };

            user.Id = Id;

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;

                foreach (var error in result.Errors)
                    errors += $"{error.Description},";

                return BadRequest( new AuthModel { Message = errors });
            }

            await _userManager.AddToRoleAsync(user, role);

            var jwtSecurityToken = await CreateJwtToken(user);

            var refreshToken = GenerateRefreshToken();

            string url_ = "https://ocalhost:7031/Auth/ConfirmEmail?code=";
            var code = _userManager.GenerateEmailConfirmationTokenAsync(user);
            string UrlForReset = url_ + code;

            //var confirmMail = Url.Action(nameof(ConfirmEmail), "Auth", new { code, email = user.Email }, Request.Scheme);
            await _mailingRepository.SendingMail(user.Email, "Confirmation Email Link", $"<a href='{UrlForReset}'>Click to confirm Sign up</a>");

            user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(user);

            return Ok (new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { role },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            });
        }


        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return Ok("Email Sent Successfully");
                }
            }

            return Ok("No Email Sent Successfully");
        }


        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.EmailOrUserName) ??
                        await _userManager.FindByNameAsync(model.EmailOrUserName);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                //return Ok(authModel);
                return BadRequest(authModel);
            }

            //if (!user.EmailConfirmed)
            //{
            //    authModel.Message = "Email is not confirmed!";
            //    return Unauthorized(authModel);
            //}

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = activeRefreshToken.Token;
                authModel.RefreshTokenExpiration = activeRefreshToken.ExpiresOn;
            }
            else
            {
                var refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
            }

            return Ok(authModel);
        }


        #region Forget Password

        [HttpPost("Forget Password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgetPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                string url_ = "https://ocalhost:7031/Auth/ResetPassword?code=";
                var code = _userManager.GeneratePasswordResetTokenAsync(user);
                string UrlForReset = url_ + code;

                await _mailingRepository.SendingMail(user.Email, "Forget Password Link", $"<a href='{UrlForReset}'></a>");

                return Ok($"Password changed request is sent on email {user.Email}, please open your email");
            }

            return BadRequest("False send email");
        }

        [HttpGet("Reset Password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new
            {
                model
            });
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null)
            {
                var resetPassword = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                if (!resetPassword.Succeeded)
                {
                    foreach(var error in resetPassword.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return Ok(ModelState);
                }

                return Ok("Password has been change");
            }

            return BadRequest("Couldnot send link to email, please try again"); 
        }

        #endregion


        #region Helpers

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }

        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];

            using var generator = new RNGCryptoServiceProvider();

            generator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(10),
                CreatedOn = DateTime.UtcNow
            };
        }

        private static string GenerateRandomID()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string nums = "0123456789";

            StringBuilder stringBuilder = new StringBuilder();

            Random random = new Random();

            for (int i =0; i < 4; i++)
            {
                stringBuilder.Append(chars[random.Next(chars.Length)]);
            }

            for (int i = 0; i < 2; i++)
            {
                stringBuilder.Append(nums[random.Next(nums.Length)]);
            }

            return stringBuilder.ToString();
        }

        #endregion
    }
}
