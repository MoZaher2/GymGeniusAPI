using GymGenius.Models.Identity;
using GymGenius.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace GymGenius.Controllers
{
    [Authorize(Roles = clsRoles.roleAdmin)]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminsController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminsController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }


        [HttpPost("AddUserToRole/{UserNameOrID}/{RoleName}")]
        public async Task<IActionResult> AddUserToRole(string UserNameOrID, string RoleName)
        {
            var user = await _userManager.FindByNameAsync(UserNameOrID);
            if (user == null)
            {
                user = await _userManager.FindByIdAsync(UserNameOrID);

                if (user == null)
                {
                    return NotFound($"User With UserNameOrID : '{UserNameOrID}' not found.");
                }
            }

            if (!await _roleManager.RoleExistsAsync(RoleName))
            {
                return BadRequest($"Role {RoleName} not found.");
            }

            await _userManager.AddToRoleAsync(user, RoleName);

            return Ok($"User {UserNameOrID} add to Role {RoleName} successfully.");
        }


        [HttpDelete("RemoveserFromRole/{UserNameOrID}/{RoleName}")]
        public async Task<IActionResult> RemoveserFromRole(string UserNameOrID, string RoleName)
        {
            var user = await _userManager.FindByNameAsync(UserNameOrID);
            if (user == null)
            {
                user = await _userManager.FindByIdAsync(UserNameOrID);

                if (user == null)
                {
                    return NotFound($"User With UserNameOrID : '{UserNameOrID}' not found.");
                }
            }

            if (!await _userManager.IsInRoleAsync(user, RoleName))
            {
                return BadRequest($"User {UserNameOrID} is not in role {RoleName}.");
            }

            await _userManager.RemoveFromRoleAsync(user, RoleName);

            return Ok($"User {UserNameOrID} Remove to Role {RoleName} successfully.");
        }


        [HttpGet("GetAllUserByRoleName/{RoleName}")]
        public async Task<IActionResult> GetAllUserByRoleName(string RoleName)
        {
            var userRole = await _userManager.GetUsersInRoleAsync(RoleName);
            if (userRole == null)
            {
                return NotFound($"No users found in role {RoleName}.");
            }

            if (!await _roleManager.RoleExistsAsync(RoleName))
            {
                return BadRequest($"Role {RoleName} not found.");
            }

            var users = userRole.Select(user => new
            {
                Id = user.Id,
                Username = user.UserName
            }).ToList();

            return Ok(users);
        }


        [HttpDelete("RemoveUser/{UserNameOrID}")]
        public async Task<IActionResult> RemoveUser(string UserNameOrID)
        {
            ApplicationUser user = new ApplicationUser();

            if (UserNameOrID.Contains("@"))
            {
                user = await _userManager.FindByNameAsync(UserNameOrID);

                if (user == null)
                {
                    return NotFound($"User With User : '{UserNameOrID}' not found.");
                }
            }
            else
            {
                user = await _userManager.FindByIdAsync(UserNameOrID);

                if (user == null)
                {
                    return NotFound($"User With ID : '{UserNameOrID}' not found.");
                }
            }

            await _userManager.DeleteAsync(user);

            return Ok($"User {UserNameOrID} delete successfully.");
        }


        [HttpGet("GetAllRoles")]
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.Select(role => new
            {
                Id = role.Id,
                Name = role.Name
            }).ToList();

            return Ok(roles);
        }
    }
}
