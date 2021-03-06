using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Waseli.Core;
using Waseli.Core.Models;
using Waseli.Persistence;

namespace Waseli
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAutoMapper(typeof(Startup));

            services.AddDbContext<WaseliDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("WaseliDbConnection")));

            services.AddIdentity<User, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.SignIn.RequireConfirmedEmail = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;
            })
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<WaseliDbContext>()
                .AddDefaultTokenProviders();

            services.AddMvc().AddNewtonsoftJson()/*.ConfigureApiBehaviorOptions(options =>
            {
                options.SuppressInferBindingSourcesForParameters = true;
            }).SetCompatibilityVersion(CompatibilityVersion.Version_3_0); */;

            services.AddScoped<ISecurityService, SecurityService>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidAudience = Configuration["JWT:ValidAudience"],
                        ValidIssuer = Configuration["JWT:ValidIssuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:Secret"])),
                        RoleClaimType = "role"
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            var dbcontext = context.HttpContext.RequestServices.GetRequiredService<WaseliDbContext>();
                            var userId = context.Principal.Claims.Where(x => x.Type == "UserId").FirstOrDefault().Value;
                            var invalidTokens = dbcontext.InvalidTokens.Where(i => i.UserId == userId).Select(i => i.Token).ToList();
                            var token = context.HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];

                            try
                            {
                                if (invalidTokens.Contains(token))
                                    context.Fail("Invalid-Token");
                                else
                                    //var jwt = (context.SecurityToken as JwtSecurityToken)?.ToString();
                                    // get your JWT token here if you need to decode it e.g on https://jwt.io
                                    // And you can re-add role claim if it has different name in token compared to what you want to use in your ClaimIdentity:  
                                    AddRoleClaims(context.Principal);
                                return Task.CompletedTask;
                            }
                            finally
                            {
                                context.HttpContext.Response.OnCompleted(async () =>
                                {
                                    var expiredValidTokens = dbcontext.ValidTokens.Where(v => v.ExpirationTime <= DateTime.Now).ToList();
                                    dbcontext.ValidTokens.RemoveRange(expiredValidTokens);

                                    var expiredInvalidTokens = dbcontext.InvalidTokens.Where(i => i.ExpirationTime <= DateTime.Now).ToList();
                                    dbcontext.InvalidTokens.RemoveRange(expiredInvalidTokens);

                                    await dbcontext.SaveChangesAsync();
                                    //dbcontext.Dispose();

                                });
                            }






                        }
                    };
                });

            services.AddAuthorization(options =>
            {
                var roles = new ApplicationRoles().GetRolePoliciess();
                foreach (var role in roles)
                    foreach (var policy in role.Policies)
                        options.AddPolicy(policy.Name, authBuilder =>
                        {
                            authBuilder.RequireRole(role.Name);
                        });

            });

            services.Configure<EmailSettings>(Configuration.GetSection("EmailSettings"));
            services.AddSingleton<IEmailSender, EmailSender>();
        }

        private static void AddRoleClaims(ClaimsPrincipal principal)
        {
            var claimsIdentity = principal.Identity as ClaimsIdentity;
            if (claimsIdentity != null)
            {
                if (claimsIdentity.HasClaim(@"http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Administrator"))
                {
                    if (!claimsIdentity.HasClaim("role", "Administrator"))
                    {
                        claimsIdentity.AddClaim(new Claim("role", "Administrator"));
                    }
                }
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            // disable http
            var options = new RewriteOptions().AddRedirectToHttpsPermanent();
            app.UseRewriter(options);

            app.UseStatusCodePages();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                //endpoints.MapRazorPages();
            });
        }
    }
}
