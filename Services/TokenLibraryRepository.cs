using System;
using System.Data;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Token.API.Entities;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Numerics;
using System.Text.Encodings.Web;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.WebUtilities;
using System.IO;
using System.Linq;

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
       

        public bool VerifyCognitoJwt(string accessToken)
        {
            string MyFilePath = "Services/jwks.json";
            JObject data = JObject.Parse(File.ReadAllText(MyFilePath));

            string[] parts = accessToken.Split('.');

            //From the Cognito JWK set
            //{"alg":"RS256","e":"myE","kid":"myKid","kty":"RSA","n":"myN","use":"sig"}]}
           
            var n = Base64UrlDecode("uEW3Epxh_xyBQ8M4xySqetDPaN2telE96tdorJGVAsIvwx8SR0mD5I19QYN4ejVOkzNNQ-pOerrZYeyxrJZShtghJqIMNMD52oqPTYPGMr56tg-FogVFu7PAiRk0WH9A38H6gtwUPYdnOloXyfWQ7sSC6f6821gui1uSaMUQIGxt8gL4qG0UBTvijD5s8nJ8WVmMVK1CraVtz4aVFQyn_jspc_zEVxd3J-K1ODnQHNO_sTeI011wtavAViaGVh-lBRazlFYX0tj9SXLC7yigNWq1KA7j6M3FfhbT2bgNOGR_bOZjFeGJQiBR_F5grJX2Cn-HRjSmn-S2Agu2hHd_UQ");
            var e = Base64UrlDecode("AQAB");

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(new RSAParameters
            {
                Exponent = new BigInteger(e).ToByteArray(),
                Modulus = new BigInteger(n).ToByteArray()
            });

            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(provider);
            rsaDeformatter.SetHashAlgorithm("SHA256");

            if (!rsaDeformatter.VerifySignature(hash, Base64UrlDecode(parts[2])))
                // throw new ApplicationException(string.Format("Invalid signature"));
                return false;

           // var tokenClaims = GetClaims(parts[0] + "." + parts[1].Trim());
          //  var userId = tokenClaims.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).FirstOrDefault().Value;

            return true;
        }

        public ClaimsPrincipal GetClaims(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false,
               // IssuerSigningKey = SIGNING_KEY,
                ValidateIssuer = false,
                ValidateAudience = false
            };

            return handler.ValidateToken(token, validations, out var tokenSecure);
        }

        // from JWT spec
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
        public class KeyData
        {
            public string Modulus { get; set; }
            public string Exponent { get; set; }
        }

        private static KeyData GetKeyData(string keys, string kid)
        {
            var keyData = new KeyData();

            dynamic obj = JObject.Parse(keys);
            var results = obj.keys;
            bool found = false;

            foreach (var key in results)
            {
                if (found)
                    break;

                if (key.kid == kid)
                {
                    keyData.Modulus = key.n;
                    keyData.Exponent = key.e;
                    found = true;
                }
            }

            return keyData;
        }



    }
}
