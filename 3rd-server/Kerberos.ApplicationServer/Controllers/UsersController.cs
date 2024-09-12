using Kerberos.ApplicationServer.Application.Dtos;
using Kerberos.ApplicationServer.Application.Processing;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Kerberos.ApplicationServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController(IUserProfileProcessingService userProfileProcessingService)
        : ControllerBase
    {
        private readonly IUserProfileProcessingService _userProfileProcessingService =
            userProfileProcessingService;

        public Task<IResult> GetUserProfileAsync(string userId)
        {
            throw new NotImplementedException();
        }
    }
}
