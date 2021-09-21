using System.Collections.Generic;

namespace Waseli.Persistence
{
    public class ApplicationRoles
    {
        private readonly IEnumerable<ApplicationRole> _roleClaims;

        public ApplicationRoles()
        {
            _roleClaims = new List<ApplicationRole>
            {
                new ApplicationRole
                {
                    Name = "Administrator",
                    Policies = new List<ApplicationPolicy>
                    {
                        new ApplicationPolicy
                        {
                            Name = "CanUpdate"
                        }
                    }
                },
                new ApplicationRole
                {
                    Name = "Accountant",
                    Policies = new List<ApplicationPolicy>
                    {
                        new ApplicationPolicy
                        {
                            Name = "CanRead"
                        }
                    }
                }
            };
        }

        public IEnumerable<ApplicationRole> GetRolePoliciess()
        {
            return _roleClaims;
        }
    }

    public class ApplicationRole
    {
        public string Name { get; set; }
        public IEnumerable<ApplicationPolicy> Policies { get; set; }
    }

    public class ApplicationPolicy
    {
        public string Name { get; set; }
    }
}
