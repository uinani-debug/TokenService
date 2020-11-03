using AutoMapper;
using TokenLibrary.API.Models;
using TokenLibrary.API.Services;
using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using TokenLibrary.API.Entities;
using Token.API.Entities;
using Token.API.Models;

namespace TokenLibrary.API.Controllers
{
    [ApiController]
  
    public class TokenController : ControllerBase
    {
        private readonly ITokenLibraryRepository _TokenLibraryRepository;
        private readonly IMapper _mapper;

        public TokenController(ITokenLibraryRepository PaymentLibraryRepository,
            IMapper mapper)
        {
            _TokenLibraryRepository = PaymentLibraryRepository ??
                throw new ArgumentNullException(nameof(PaymentLibraryRepository));
            _mapper = mapper ??
                throw new ArgumentNullException(nameof(mapper));
        }

        [Route("api/v1/GenerateToken")]
        [HttpPost]
        public ActionResult<GenerateTokenResponse> PopulateToken(GenerateTokenRequest  generateTokenRequest)
        {
            try
            {

                if (generateTokenRequest != null || generateTokenRequest.scope != null || generateTokenRequest.userid != null)

                {
                    var tokenInfo = _TokenLibraryRepository.GenerateTokenRequest(generateTokenRequest.userid,
                        generateTokenRequest.scope);


                    if (tokenInfo == null || tokenInfo.Length < 0)
                    {
                        var error = new Error() { ErrorMessage = "Token Expired or Invalid Key or Token Verification Failed" };
                        return Unauthorized(error);
                    }

                    return Ok(tokenInfo);
                }
                else
                    return BadRequest();
            }
            catch (Exception ex)
            {
                var error = new Error() { ErrorMessage = "Token Expired or Invalid Key or Token Verification Failed" };
                return Unauthorized(error);
            }
           
        }


        [Route("api/v1/ValidateToken")]
        [HttpPost]
        public ActionResult<ValidateTokenResponse> CheckToken(ValidateTokenRequest validateTokenRequest)
        {
            try
            {

                if (validateTokenRequest != null || validateTokenRequest.JWTToken != null)

                {
                    var tokenClaim = _TokenLibraryRepository.ValidateTokenClaim(validateTokenRequest.JWTToken);


                    if (tokenClaim == null)
                    {
                        var error = new Error() { ErrorMessage = "Token Expired or Invalid Key or Token Verification Failed" };
                        return Unauthorized(error);
                    }
                    return Ok(tokenClaim);
                }
                else
                    return BadRequest();
            }

            catch (Exception ex)

            {
                var error = new Error() { ErrorMessage = "Token Expired or Invalid Key or Token Verification Failed" };
                return Unauthorized(error);
            }

}


        public override ActionResult ValidationProblem(
            [ActionResultObjectValue] ModelStateDictionary modelStateDictionary)
        {
            var options = HttpContext.RequestServices
                .GetRequiredService<IOptions<ApiBehaviorOptions>>();
            return (ActionResult)options.Value.InvalidModelStateResponseFactory(ControllerContext);
        }
    }
}