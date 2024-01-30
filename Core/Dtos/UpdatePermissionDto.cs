using System.ComponentModel.DataAnnotations;

namespace JWT.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage ="UserName is Required")]
        public string UserName { get; set; }
    }
}
