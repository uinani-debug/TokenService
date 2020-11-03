using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Token.API.Entities
{
    public class ValidateTokenResponse
    {
        public string userid { get; set; }
        public string scope { get; set; }
    }
}
