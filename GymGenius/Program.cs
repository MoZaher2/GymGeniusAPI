﻿using GymGenius.Data;
using GymGenius.Helpers;
using GymGenius.Models.Email;
using GymGenius.Models.Identity;
using GymGenius.Services.Interface;
using GymGenius.Services.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json.Serialization;
using System;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container & Connect between JS & C#
// Shared Resource 

builder.Services.AddControllersWithViews()
    .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
    .AddDataAnnotationsLocalization()
    .AddNewtonsoftJson(opt => {
        opt.SerializerSettings.ContractResolver = new DefaultContractResolver();
    });

builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

#region Dependency Injection Settings

builder.Services.AddScoped(typeof(IAdvertisementRepository), typeof(AdvertisementRepository));

builder.Services.AddScoped(typeof(IOfferRepository), typeof(OfferRepository));

builder.Services.AddScoped(typeof(INotificationRepository), typeof(NotificationRepository));

builder.Services.AddScoped(typeof(IShapeRepository), typeof(ShapeRepository));

builder.Services.AddScoped(typeof(IplanRepository), typeof(planRepository));

builder.Services.AddScoped(typeof(ISubscriptionRepository), typeof(SubscriptionRepository));

builder.Services.AddScoped(typeof(IMailingRepository), typeof(MailingRepository));

#endregion


#region JWT

builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = false;
        o.SaveToken = true;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["JWT:Issuer"],
            ValidAudience = builder.Configuration["JWT:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
            ClockSkew = TimeSpan.Zero
        };
    });

#endregion

// Chat

builder.Services.AddSignalR();

// Adding Config For Required Email

builder.Services.Configure<IdentityOptions>(options => options.SignIn.RequireConfirmedEmail = true);

builder.Services.Configure<MailSetting>(builder.Configuration.GetSection("MailSetting"));

// ConnectionStrings

builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("Defult"))
    );

// Auto Mapper

builder.Services.AddAutoMapper(m => m.AddProfile(new AutoMapperProfile()));

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "GymGenius", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
});

////
//builder.Services.AddCors(options =>
//{
//    options.AddPolicy("AllowLocalhost3000",
//        builder =>
//        {
//            builder.WithOrigins("http://localhost:3000", "https://c5f3-197-59-69-99.ngrok-free.app", "http://127.0.0.1:5500")
//                   .AllowAnyHeader()
//                   .AllowAnyMethod();
//        });
//});
////
//
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAnyOriginPolicy",
        builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyHeader()
                   .AllowAnyMethod();
        });
});
//

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


//if (app.Environment.IsDevelopment())
//{
//    // إلغاء طلب HTTPS لمنطقة Swagger فقط
//    app.Use((context, next) =>
//    {
//        if (context.Request.Path.StartsWithSegments("/swagger") && context.Request.IsHttps)
//        {
//            context.Request.Scheme = "http";
//            context.Request.Protocol = "http";
//            context.Request.IsHttps = false;
//        }
//        return next();
//    });
//    app.UseSwagger();
//    app.UseSwaggerUI();
//}








app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapHub<ChatHub>("/chatHub");

////
//app.UseCors("AllowLocalhost3000");
////

//
app.UseCors("AllowAnyOriginPolicy");
//

app.Run();
