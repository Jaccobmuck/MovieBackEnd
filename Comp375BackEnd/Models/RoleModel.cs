using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Comp375BackEnd.Models
{
    [Table("Role")]
    public class RoleModel
    {
        [Key]
        public long RoleId { get; set; }
        public string Name { get; set; } = string.Empty;
    }
}
