using System.ComponentModel.DataAnnotations;

namespace API.DTO
{
    public class RegisterDTO
    {
        [RequiredAttribute]  
        public string Username { get; set; }

         [Required]
        public string Password { get; set; }
    }
}