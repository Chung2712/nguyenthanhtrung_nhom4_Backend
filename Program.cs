using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NguyenThanhTrung_SmartGuard_API.Models;
using NguyenThanhTrung_SmartGuard_API.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var jwtKey = builder.Configuration["Jwt:Key"];
if (string.IsNullOrWhiteSpace(jwtKey) || Encoding.UTF8.GetByteCount(jwtKey) < 32)
    throw new InvalidOperationException("Jwt:Key must be set and contain at least 32 UTF-8 bytes. Do not use the development key in production.");
if (!builder.Environment.IsDevelopment() &&
    (jwtKey.StartsWith("SMARTGUARD_DEVELOPMENT_ONLY", StringComparison.Ordinal) ||
     string.IsNullOrWhiteSpace(builder.Configuration["Smtp:Host"])))
    throw new InvalidOperationException("Production requires its own JWT key and working SMTP configuration.");

builder.Services.AddDbContext<SmartGuardDb>(opts =>
    opts.UseSqlServer(builder.Configuration.GetConnectionString("Default"), sql => sql.EnableRetryOnFailure()));
builder.Services.AddScoped<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true, ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});     
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OwnerOrAdmin", policy => policy.RequireRole("Owner", "Admin"));
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 12,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// MVP initialization. For subsequent schema changes, migrate to EF Core Migrations.
// Initialize SQL Server using EF Core Migrations.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SmartGuardDb>();

    await db.Database.MigrateAsync();

    var adminUsername = app.Configuration["BootstrapAdmin:Username"];
    var adminEmail = app.Configuration["BootstrapAdmin:Email"];
    var adminPassword = app.Configuration["BootstrapAdmin:Password"];

    if (!string.IsNullOrWhiteSpace(adminUsername) &&
        !string.IsNullOrWhiteSpace(adminEmail) &&
        !string.IsNullOrWhiteSpace(adminPassword) &&
        adminPassword.Length >= 12 &&
        !await db.Users.AnyAsync(u =>
            u.Username == adminUsername.ToLowerInvariant()))
    {
        var user = new AppUser
        {
            Username = adminUsername.Trim().ToLowerInvariant(),
            Email = adminEmail.Trim().ToLowerInvariant(),
            Role = "Admin",
            EmailVerified = true
        };

        user.PasswordHash = scope.ServiceProvider
            .GetRequiredService<IPasswordHasher<AppUser>>()
            .HashPassword(user, adminPassword);

        db.Users.Add(user);
        await db.SaveChangesAsync();
    }
}

app.MapGet("/api/health", () => Results.Ok(new { status = "ok", application = "SmartGuard API" }));

var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");
auth.MapPost("/register", async (RegisterRequest req, SmartGuardDb db,
    IPasswordHasher<AppUser> hasher, IConfiguration config, IHostEnvironment env) =>
{
    var username = (req.Username ?? "").Trim().ToLowerInvariant();
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    if (username.Length is < 3 or > 50 || !System.Net.Mail.MailAddress.TryCreate(email, out _) ||
        req.Password is null || req.Password.Length < 8)
        return Results.BadRequest(new { error = "Tên đăng nhập >= 3 ký tự, email hợp lệ và mật khẩu >= 8 ký tự." });
    if (await db.Users.AnyAsync(u => u.Username == username || u.Email == email))
        return Results.Conflict(new { error = "Tên đăng nhập hoặc email đã tồn tại." });
    var user = new AppUser { Username = username, Email = email };
    user.PasswordHash = hasher.HashPassword(user, req.Password);
    db.Users.Add(user);
    await db.SaveChangesAsync();
    var (challenge, code) = AddChallenge(db, user.Id, "VerifyEmail", config["Jwt:Key"]!);
    await db.SaveChangesAsync();
    var devOtp = await Security.SendOtpAsync(email, code, "VerifyEmail", config, env);
    return Results.Ok(new { challengeId = challenge.Id, message = "Nhập OTP để xác minh email.", developmentOtp = devOtp });
});

auth.MapPost("/verify-email", async (VerifyEmailRequest req, SmartGuardDb db, IConfiguration config) =>
{
    var challenge = await db.OtpChallenges.FirstOrDefaultAsync(c => c.Id == req.ChallengeId && c.Purpose == "VerifyEmail");
    if (!ConsumeChallenge(challenge, req.Code ?? "", config["Jwt:Key"]!))
    {
        await db.SaveChangesAsync();
        return Results.BadRequest(new { error = "OTP không đúng, hết hạn hoặc quá số lần thử." });
    }
    var user = await db.Users.FindAsync(challenge!.UserId);
    if (user is null) return Results.NotFound();
    user.EmailVerified = true;
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Email đã xác minh. Bạn có thể đăng nhập." });
});

auth.MapPost("/login", async (LoginRequest req, SmartGuardDb db,
    IPasswordHasher<AppUser> hasher, IConfiguration config, IHostEnvironment env) =>
{
    var username = (req.Username ?? "").Trim().ToLowerInvariant();
    var user = await db.Users.FirstOrDefaultAsync(x => x.Username == username);
    if (user is null || req.Password is null ||
        hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password) == PasswordVerificationResult.Failed)
        return Results.Unauthorized();
    if (!user.EmailVerified) return Results.BadRequest(new { error = "Bạn cần xác minh email trước." });
    var (challenge, code) = AddChallenge(db, user.Id, "Login", config["Jwt:Key"]!);
    await db.SaveChangesAsync();
    var devOtp = await Security.SendOtpAsync(user.Email, code, "Login", config, env);
    return Results.Ok(new { challengeId = challenge.Id, message = "OTP đăng nhập đã được gửi.", developmentOtp = devOtp });
});

auth.MapPost("/verify-login", async (VerifyLoginRequest req, SmartGuardDb db, IConfiguration config) =>
{
    var challenge = await db.OtpChallenges.FirstOrDefaultAsync(c => c.Id == req.ChallengeId && c.Purpose == "Login");
    if (!ConsumeChallenge(challenge, req.Code ?? "", config["Jwt:Key"]!))
    {
        await db.SaveChangesAsync();
        return Results.BadRequest(new { error = "OTP không đúng, hết hạn hoặc quá số lần thử." });
    }
    var user = await db.Users.FindAsync(challenge!.UserId);
    if (user is null || !user.EmailVerified) return Results.Unauthorized();
    await db.SaveChangesAsync();
    return Results.Ok(new
    {
        accessToken = Security.CreateJwt(user, config),
        role = user.Role, username = user.Username, expiresInSeconds = 28800
    });
});

app.MapGet("/api/me", async (ClaimsPrincipal principal, SmartGuardDb db) =>
{
    var id = Security.UserId(principal);
    return await db.Users.Where(x => x.Id == id)
        .Select(x => new { x.Id, x.Username, x.Email, x.Role })
        .FirstOrDefaultAsync() is { } user ? Results.Ok(user) : Results.Unauthorized();
}).RequireAuthorization();

var zones = app.MapGroup("/api/zones").RequireAuthorization();
zones.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) =>
    Results.Ok(await db.Zones.Where(z => z.OwnerId == Security.UserId(p))
        .OrderBy(z => z.Name).Select(z => new { z.Id, z.Name, z.Description }).ToListAsync()));
zones.MapGet("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
    await db.Zones.Where(z => z.Id == id && z.OwnerId == Security.UserId(p))
        .Select(z => new { z.Id, z.Name, z.Description }).FirstOrDefaultAsync() is { } zone
        ? Results.Ok(zone) : Results.NotFound());
zones.MapPost("/", async (ZoneRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    if (!ValidName(req.Name)) return Results.BadRequest(new { error = "Tên khu vực phải từ 1 đến 100 ký tự." });
    var zone = new Zone { OwnerId = Security.UserId(p), Name = req.Name.Trim(), Description = (req.Description ?? "").Trim() };
    db.Zones.Add(zone); await db.SaveChangesAsync();
    return Results.Created($"/api/zones/{zone.Id}", zone);
}).RequireAuthorization("OwnerOrAdmin");
zones.MapPut("/{id:guid}", async (Guid id, ZoneRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var z = await db.Zones.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (z is null) return Results.NotFound();
    if (!ValidName(req.Name)) return Results.BadRequest(new { error = "Tên khu vực không hợp lệ." });
    z.Name = req.Name.Trim(); z.Description = (req.Description ?? "").Trim();
    await db.SaveChangesAsync(); return Results.Ok(z);
}).RequireAuthorization("OwnerOrAdmin");
zones.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var z = await db.Zones.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (z is null) return Results.NotFound();
    await db.Devices.Where(d => d.OwnerId == Security.UserId(p) && d.ZoneId == id)
        .ExecuteUpdateAsync(s => s.SetProperty(d => d.ZoneId, (Guid?)null));
    db.Zones.Remove(z); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization("OwnerOrAdmin");

var configs = app.MapGroup("/api/configs").RequireAuthorization();
configs.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) => Results.Ok(await db.AlarmConfigs
    .Where(c => c.OwnerId == Security.UserId(p)).OrderBy(c => c.Name).ToListAsync()));
configs.MapGet("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
    await db.AlarmConfigs.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p)) is { } c
        ? Results.Ok(c) : Results.NotFound());
configs.MapPost("/", async (ConfigRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    if (!ValidConfig(req)) return Results.BadRequest(new { error = "Tên, độ nhạy (1-10), âm lượng (0-100) hoặc độ trễ (0-60) không hợp lệ." });
    var config = new AlarmConfig { OwnerId = Security.UserId(p), Name = req.Name.Trim(),
        Sensitivity = req.Sensitivity, AlarmVolume = req.AlarmVolume, DelaySeconds = req.DelaySeconds };
    db.AlarmConfigs.Add(config); await db.SaveChangesAsync();
    return Results.Created($"/api/configs/{config.Id}", config);
}).RequireAuthorization("OwnerOrAdmin");
configs.MapPut("/{id:guid}", async (Guid id, ConfigRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var config = await db.AlarmConfigs.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (config is null) return Results.NotFound();
    if (!ValidConfig(req)) return Results.BadRequest(new { error = "Cấu hình không hợp lệ." });
    config.Name = req.Name.Trim(); config.Sensitivity = req.Sensitivity;
    config.AlarmVolume = req.AlarmVolume; config.DelaySeconds = req.DelaySeconds;
    await db.SaveChangesAsync(); return Results.Ok(config);
}).RequireAuthorization("OwnerOrAdmin");
configs.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var c = await db.AlarmConfigs.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (c is null) return Results.NotFound();
    await db.Devices.Where(x => x.OwnerId == Security.UserId(p) && x.ConfigId == id)
        .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConfigId, (Guid?)null));
    db.AlarmConfigs.Remove(c); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization("OwnerOrAdmin");

var devices = app.MapGroup("/api/devices").RequireAuthorization();
devices.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) =>
{
    var id = Security.UserId(p);
    var role = p.FindFirstValue(ClaimTypes.Role);
    var accessible = role == "Member"
        ? db.Devices.Where(d => db.MemberAccesses.Any(m => m.MemberUserId == id && m.OwnerId == d.OwnerId &&
            (m.DeviceId == null || m.DeviceId == d.Id)))
        : db.Devices.Where(d => d.OwnerId == id);
    return Results.Ok(await accessible.OrderBy(x => x.Name).Select(x => new
    { x.Id, x.Name, x.DeviceCode, x.Description, x.ZoneId, x.ConfigId, x.IsArmed }).ToListAsync());
});
devices.MapGet("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var userId = Security.UserId(p);
    var device = await db.Devices.FirstOrDefaultAsync(d => d.Id == id &&
        (d.OwnerId == userId || db.MemberAccesses.Any(m => m.MemberUserId == userId &&
            m.OwnerId == d.OwnerId && (m.DeviceId == null || m.DeviceId == id))));
    return device is null ? Results.NotFound() : Results.Ok(device);
});
devices.MapPost("/", async (DeviceRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var id = Security.UserId(p);
    if (!ValidName(req.Name) || string.IsNullOrWhiteSpace(req.DeviceCode) || req.DeviceCode.Length > 60)
        return Results.BadRequest(new { error = "Tên hoặc mã thiết bị không hợp lệ." });
    var code = req.DeviceCode.Trim();
    if (await db.Devices.AnyAsync(x => x.DeviceCode == code))
        return Results.Conflict(new { error = "Mã thiết bị đã tồn tại." });
    if (!await ValidReferences(db, id, req.ZoneId, req.ConfigId))
        return Results.BadRequest(new { error = "Khu vực hoặc cấu hình không thuộc tài khoản." });
    var d = new GuardDevice { OwnerId = id, Name = req.Name.Trim(), DeviceCode = code,
        Description = (req.Description ?? "").Trim(), ZoneId = req.ZoneId,
        ConfigId = req.ConfigId, IsArmed = req.IsArmed };
    db.Devices.Add(d); await db.SaveChangesAsync();
    return Results.Created($"/api/devices/{d.Id}", d);
}).RequireAuthorization("OwnerOrAdmin");
devices.MapPut("/{id:guid}", async (Guid id, DeviceRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var uid = Security.UserId(p);
    var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == uid);
    if (d is null) return Results.NotFound();
    if (!ValidName(req.Name) || string.IsNullOrWhiteSpace(req.DeviceCode) || req.DeviceCode.Length > 60)
        return Results.BadRequest(new { error = "Tên hoặc mã thiết bị không hợp lệ." });
    var code = req.DeviceCode.Trim();
    if (await db.Devices.AnyAsync(x => x.Id != id && x.DeviceCode == code))
        return Results.Conflict(new { error = "Mã thiết bị đã tồn tại." });
    if (!await ValidReferences(db, uid, req.ZoneId, req.ConfigId))
        return Results.BadRequest(new { error = "Khu vực hoặc cấu hình không thuộc tài khoản." });
    d.Name = req.Name.Trim(); d.DeviceCode = code; d.Description = (req.Description ?? "").Trim();
    d.ZoneId = req.ZoneId; d.ConfigId = req.ConfigId; d.IsArmed = req.IsArmed;
    await db.SaveChangesAsync(); return Results.Ok(d);
}).RequireAuthorization("OwnerOrAdmin");
devices.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (d is null) return Results.NotFound();
    // Clear dependent rows intentionally rather than cascading across owners.
    await db.MemberAccesses.Where(x => x.DeviceId == id).ExecuteDeleteAsync();
    await db.AlarmEvents.Where(x => x.DeviceId == id).ExecuteDeleteAsync();
    await db.DeviceLocations.Where(x => x.DeviceId == id).ExecuteDeleteAsync();
    db.Devices.Remove(d); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization("OwnerOrAdmin");

var members = app.MapGroup("/api/members").RequireAuthorization("OwnerOrAdmin");
members.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) =>
{
    var id = Security.UserId(p);
    return Results.Ok(await (from a in db.MemberAccesses
        join u in db.Users on a.MemberUserId equals u.Id
        where a.OwnerId == id
        orderby u.Email
        select new { a.Id, a.MemberUserId, memberEmail = u.Email, a.DeviceId,
            a.CanAcknowledge }).ToListAsync());
});
members.MapGet("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
    await db.MemberAccesses.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p)) is { } m
        ? Results.Ok(m) : Results.NotFound());
members.MapPost("/", async (MemberRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var ownerId = Security.UserId(p);
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    var member = await db.Users.FirstOrDefaultAsync(x => x.Email == email && x.EmailVerified);
    if (member is null || member.Id == ownerId)
        return Results.BadRequest(new { error = "Thành viên phải có tài khoản đã xác minh và khác chủ sở hữu." });
    if (!await ValidMemberDevice(db, ownerId, req.DeviceId))
        return Results.BadRequest(new { error = "Thiết bị không thuộc tài khoản." });
    if (await db.MemberAccesses.AnyAsync(x => x.OwnerId == ownerId && x.MemberUserId == member.Id && x.DeviceId == req.DeviceId))
        return Results.Conflict(new { error = "Quyền truy cập đã tồn tại." });
    var access = new MemberAccess { OwnerId = ownerId, MemberUserId = member.Id,
        DeviceId = req.DeviceId, CanAcknowledge = req.CanAcknowledge };
    db.MemberAccesses.Add(access); await db.SaveChangesAsync();
    return Results.Created($"/api/members/{access.Id}", access);
});
members.MapPut("/{id:guid}", async (Guid id, MemberUpdateRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var ownerId = Security.UserId(p);
    var a = await db.MemberAccesses.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == ownerId);
    if (a is null) return Results.NotFound();
    if (!await ValidMemberDevice(db, ownerId, req.DeviceId))
        return Results.BadRequest(new { error = "Thiết bị không thuộc tài khoản." });
    if (await db.MemberAccesses.AnyAsync(x => x.Id != id && x.OwnerId == ownerId &&
        x.MemberUserId == a.MemberUserId && x.DeviceId == req.DeviceId))
        return Results.Conflict(new { error = "Quyền truy cập đã tồn tại." });
    a.DeviceId = req.DeviceId; a.CanAcknowledge = req.CanAcknowledge;
    await db.SaveChangesAsync(); return Results.Ok(a);
});
members.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var a = await db.MemberAccesses.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == Security.UserId(p));
    if (a is null) return Results.NotFound();
    db.MemberAccesses.Remove(a); await db.SaveChangesAsync(); return Results.NoContent();
});

// Latest device position, shared only when the owner explicitly taps "send location".
var locations = app.MapGroup("/api/locations").RequireAuthorization();
locations.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) =>
{
    var userId = Security.UserId(p);
    var data = await (from l in db.DeviceLocations
        join d in db.Devices on l.DeviceId equals d.Id
        where d.OwnerId == userId || db.MemberAccesses.Any(m => m.MemberUserId == userId &&
            m.OwnerId == d.OwnerId && (m.DeviceId == null || m.DeviceId == d.Id))
        orderby l.UpdatedAt descending
        select new { l.DeviceId, deviceName = d.Name, l.Latitude, l.Longitude,
            l.AccuracyMeters, l.UpdatedAt }).ToListAsync();
    return Results.Ok(data);
});
locations.MapPost("/devices/{deviceId:guid}", async (Guid deviceId, LocationUpdateRequest req,
    ClaimsPrincipal p, SmartGuardDb db) =>
{
    if (!double.IsFinite(req.Latitude) || req.Latitude is < -90 or > 90 ||
        !double.IsFinite(req.Longitude) || req.Longitude is < -180 or > 180 ||
        !double.IsFinite(req.AccuracyMeters) || req.AccuracyMeters is < 0 or > 100000)
        return Results.BadRequest(new { error = "Tọa độ hoặc độ chính xác không hợp lệ." });
    if (!await db.Devices.AnyAsync(d => d.Id == deviceId && d.OwnerId == Security.UserId(p)))
        return Results.NotFound();
    var position = await db.DeviceLocations.FindAsync(deviceId);
    if (position is null)
    {
        position = new DeviceLocation { DeviceId = deviceId };
        db.DeviceLocations.Add(position);
    }
    position.Latitude = req.Latitude;
    position.Longitude = req.Longitude;
    position.AccuracyMeters = req.AccuracyMeters;
    position.UpdatedAt = DateTimeOffset.UtcNow;
    await db.SaveChangesAsync();
    return Results.Ok(new { position.DeviceId, position.Latitude, position.Longitude,
        position.AccuracyMeters, position.UpdatedAt });
}).RequireAuthorization("OwnerOrAdmin");

var events = app.MapGroup("/api/events").RequireAuthorization();
events.MapGet("/", async (ClaimsPrincipal p, SmartGuardDb db) =>
{
    var id = Security.UserId(p);
    var list = await (from e in db.AlarmEvents
        join d in db.Devices on e.DeviceId equals d.Id
        where d.OwnerId == id || db.MemberAccesses.Any(m => m.MemberUserId == id &&
            m.OwnerId == d.OwnerId && (m.DeviceId == null || m.DeviceId == d.Id))
        orderby e.OccurredAt descending
        select new { e.Id, e.DeviceId, deviceName = d.Name, e.MotionScore, e.Severity,
            e.OccurredAt, e.AcknowledgedAt }).Take(100).ToListAsync();
    return Results.Ok(list);
});
events.MapPost("/devices/{deviceId:guid}", async (Guid deviceId, EventRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    if (!double.IsFinite(req.MotionScore) || req.MotionScore < 0 || req.MotionScore > 100)
        return Results.BadRequest(new { error = "MotionScore không hợp lệ (0-100)." });
    var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == deviceId && x.OwnerId == Security.UserId(p));
    if (d is null) return Results.NotFound();
    if (!d.IsArmed) return Results.BadRequest(new { error = "Thiết bị chưa được bật bảo vệ." });
    var e = new AlarmEvent { DeviceId = deviceId, MotionScore = req.MotionScore,
        Severity = req.MotionScore >= 8 ? "Critical" : req.MotionScore >= 4 ? "Warning" : "Low" };
    db.AlarmEvents.Add(e); await db.SaveChangesAsync();
    return Results.Created($"/api/events/{e.Id}", e);
}).RequireAuthorization("OwnerOrAdmin");
events.MapPost("/{id:guid}/acknowledge", async (Guid id, ClaimsPrincipal p, SmartGuardDb db) =>
{
    var uid = Security.UserId(p);
    var e = await (from ev in db.AlarmEvents
        join d in db.Devices on ev.DeviceId equals d.Id
        where ev.Id == id && (d.OwnerId == uid || db.MemberAccesses.Any(m => m.MemberUserId == uid &&
            m.OwnerId == d.OwnerId && m.CanAcknowledge && (m.DeviceId == null || m.DeviceId == d.Id)))
        select ev).FirstOrDefaultAsync();
    if (e is null) return Results.NotFound();
    if (e.AcknowledgedAt is null) { e.AcknowledgedBy = uid; e.AcknowledgedAt = DateTimeOffset.UtcNow; }
    await db.SaveChangesAsync(); return Results.Ok(e);
});

var admin = app.MapGroup("/api/admin").RequireAuthorization("AdminOnly");
admin.MapGet("/summary", async (SmartGuardDb db) => Results.Ok(new
{
    userCount = await db.Users.CountAsync(), deviceCount = await db.Devices.CountAsync(),
    eventCount = await db.AlarmEvents.CountAsync()
}));
admin.MapGet("/users", async (SmartGuardDb db) => Results.Ok(await db.Users.OrderBy(x => x.Username)
    .Select(u => new { u.Id, u.Username, u.Email, u.Role, u.EmailVerified }).ToListAsync()));
admin.MapPut("/users/{id:guid}/role", async (Guid id, UserRoleRequest req, ClaimsPrincipal p, SmartGuardDb db) =>
{
    if (req.Role is not ("Member" or "Owner"))
        return Results.BadRequest(new { error = "Chỉ được chuyển vai trò Member/Owner." });
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();
    if (user.Role == "Admin" || user.Id == Security.UserId(p))
        return Results.BadRequest(new { error = "Không thay đổi vai trò quản trị viên." });
    user.Role = req.Role;
    await db.SaveChangesAsync();
    return Results.Ok(new { user.Id, user.Role });
});

app.Run();

static bool ValidName(string? name) => !string.IsNullOrWhiteSpace(name) && name.Trim().Length <= 100;
static bool ValidConfig(ConfigRequest r) => ValidName(r.Name) && r.Sensitivity is >= 1 and <= 10 &&
    r.AlarmVolume is >= 0 and <= 100 && r.DelaySeconds is >= 0 and <= 60;
static async Task<bool> ValidReferences(SmartGuardDb db, Guid uid, Guid? zid, Guid? cid) =>
    (zid is null || await db.Zones.AnyAsync(x => x.Id == zid && x.OwnerId == uid)) &&
    (cid is null || await db.AlarmConfigs.AnyAsync(x => x.Id == cid && x.OwnerId == uid));
static async Task<bool> ValidMemberDevice(SmartGuardDb db, Guid uid, Guid? deviceId) =>
    deviceId is null || await db.Devices.AnyAsync(x => x.Id == deviceId && x.OwnerId == uid);
static (OtpChallenge challenge, string otp) AddChallenge(SmartGuardDb db, Guid userId,
    string purpose, string secret)
{
    var code = Security.GenerateOtp();
    var challenge = new OtpChallenge
    {
        UserId = userId, Purpose = purpose, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
    };
    challenge.CodeHash = Security.HashOtp(challenge.Id, code, secret);
    db.OtpChallenges.Add(challenge);
    return (challenge, code);
}
static bool ConsumeChallenge(OtpChallenge? challenge, string code, string secret)
{
    if (challenge is null || challenge.UsedAt is not null ||
        challenge.ExpiresAt < DateTimeOffset.UtcNow || challenge.Attempts >= 5)
        return false;
    challenge.Attempts++;
    if (!Security.VerifyOtp(challenge, code, secret)) return false;
    challenge.UsedAt = DateTimeOffset.UtcNow;
    return true;
}
