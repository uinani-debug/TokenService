using TokenLibrary.API.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using Dapper;
using System.Data;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Token.API.Entities;

namespace TokenLibrary.API.Services
{
    public class TokenLibraryRepository : ITokenLibraryRepository, IDisposable
    {

        private readonly string connstring;
        private IDbConnection Connection => new SqlConnection(connstring);
        public TokenLibraryRepository()
        {

            //  connstring = "Server=192.168.0.164;Database=maecbsdb;user=SA;Password=TCSuser1123;Trusted_Connection=True;";
           // connstring = "Server=192.168.0.164;Database=maecbsdb;user=SA;Password=TCSuser1123;";
        }



        public string GenerateTokenRequest(string userid, string scope)
        {
            try
            {
                string jwtSecretKey = "secretkeymohanakrishnan";
                byte[] key = Encoding.ASCII.GetBytes(jwtSecretKey);
                SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
                SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    { new Claim("custom:CustomerId", userid),
                  new Claim("scope", scope)
                }),
                    Expires = DateTime.UtcNow.AddHours(2),
                    SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
                };

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
                return handler.WriteToken(token);
            }
            catch(Exception ex)
            {
                return null;
            }
        }




        public ValidateTokenResponse ValidateTokenClaim(string jWTToken)
        {
            try
            {
                ClaimsPrincipal principal = GetPrincipal(jWTToken);
                if (principal == null)
                    return null;
                var identity = (ClaimsIdentity)principal.Identity;
                Claim pTokenClaimScope = identity.FindFirst("scope");
                Claim pTokenCLaimUserId = identity.FindFirst("custom:CustomerId");

                var validateTokenResponse = new ValidateTokenResponse()
                {
                    scope = pTokenClaimScope.Value,
                    userid = pTokenCLaimUserId.Value
                };

                return validateTokenResponse;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private ClaimsPrincipal GetPrincipal(string token)
        {
            string jwtSecretKey = "secretkeymohanakrishnan";
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadJwtToken(token);
            if(jwtToken == null) { return null; }
            byte[] key = Encoding.ASCII.GetBytes(jwtSecretKey.Trim());

            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);

            TokenValidationParameters parameters = new TokenValidationParameters()
            {
                RequireExpirationTime = true,
                ValidateIssuer = false,
                ValidateAudience=false,
                ValidateIssuerSigningKey=false,
                IssuerSigningKey = securityKey

            };


            SecurityToken securityToken;
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
            return principal;
        }




        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // dispose resources when needed
            }
        }

       
    }
}
