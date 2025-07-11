﻿using Comp375BackEnd.Models;
using Microsoft.EntityFrameworkCore;

namespace Comp375BackEnd.Data
{
    public class MyContext : DbContext
    {
        public MyContext(DbContextOptions<MyContext> options) : base(options) { }

        public DbSet<GenreModel> Genre { get; set; }
        public DbSet<MovieModel> Movie { get; set; }
        public DbSet<UserSaveModel> UserSave { get; set; }
        public DbSet<UserModel> User { get; set; }
        public DbSet<RoleModel> Role { get; set; }
    }
}
