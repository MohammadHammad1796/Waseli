using AutoMapper;
using Waseli.Core.Models;

namespace Waseli.Persistence
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ValidToken, InvalidToken>()
                .ForMember(i => i.Id, opt => opt.Ignore());
        }
    }
}
