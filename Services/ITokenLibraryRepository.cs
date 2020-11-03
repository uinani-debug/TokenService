using TokenLibrary.API.Entities;
using System.Collections.Generic;
using Token.API.Entities;

namespace TokenLibrary.API.Services
{
    public interface ITokenLibraryRepository
    {  
       
       
        string GenerateTokenRequest(string userid, string scope);
        ValidateTokenResponse ValidateTokenClaim(string jWTToken);
    }
}
