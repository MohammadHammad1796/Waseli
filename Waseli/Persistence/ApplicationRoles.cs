using System.Collections.Generic;

namespace Waseli.Persistence
{
    public class ApplicationRoles
    {
        private readonly IEnumerable<Role> _roleClaims;

        public ApplicationRoles()
        {
            _roleClaims = new List<Role>
            {
                new Role
                {
                    Name = "Administrator",
                    Policies = new List<Policy>
                    {
                        new Policy
                        {
                            Name = "CanUpdate"
                        }
                    }
                },
                new Role
                {
                    Name = "Accountant",
                    Policies = new List<Policy>
                    {
                        new Policy
                        {
                            Name = "CanRead"
                        }
                    }
                }
            };
        }

        public IEnumerable<Role> GetRolePoliciess()
        {
            return _roleClaims;
        }
    }

    public class Role
    {
        public string Name { get; set; }
        public IEnumerable<Policy> Policies { get; set; }
    }

    public class Policy
    {
        public string Name { get; set; }
    }
}
