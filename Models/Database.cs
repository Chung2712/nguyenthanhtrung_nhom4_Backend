using Microsoft.EntityFrameworkCore;

namespace NguyenThanhTrung_SmartGuard_API.Models;

public class AppUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "Owner"; // Admin | Owner | Member
    public bool EmailVerified { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class OtpChallenge
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string Purpose { get; set; } = ""; // VerifyEmail | Login
    public string CodeHash { get; set; } = "";
    public int Attempts { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public class Zone
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OwnerId { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
}

public class AlarmConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OwnerId { get; set; }
    public string Name { get; set; } = "";
    public int Sensitivity { get; set; } = 5; // 1..10
    public int AlarmVolume { get; set; } = 80; // 0..100
    public int DelaySeconds { get; set; } = 0; // 0..60
}

public class GuardDevice
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OwnerId { get; set; }
    public string Name { get; set; } = "";
    public string DeviceCode { get; set; } = "";
    public string Description { get; set; } = "";
    public Guid? ZoneId { get; set; }
    public Guid? ConfigId { get; set; }
    public bool IsArmed { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class MemberAccess
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OwnerId { get; set; }
    public Guid MemberUserId { get; set; }
    public Guid? DeviceId { get; set; } // null => access to all owner's devices
    public bool CanAcknowledge { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class AlarmEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DeviceId { get; set; }
    public double MotionScore { get; set; }
    public string Severity { get; set; } = "Warning";
    public DateTimeOffset OccurredAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? AcknowledgedBy { get; set; }
    public DateTimeOffset? AcknowledgedAt { get; set; }
}

public class DeviceLocation
{
    public Guid DeviceId { get; set; }
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public double AccuracyMeters { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class SmartGuardDb(DbContextOptions<SmartGuardDb> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<OtpChallenge> OtpChallenges => Set<OtpChallenge>();
    public DbSet<Zone> Zones => Set<Zone>();
    public DbSet<AlarmConfig> AlarmConfigs => Set<AlarmConfig>();
    public DbSet<GuardDevice> Devices => Set<GuardDevice>();
    public DbSet<MemberAccess> MemberAccesses => Set<MemberAccess>();
    public DbSet<AlarmEvent> AlarmEvents => Set<AlarmEvent>();
    public DbSet<DeviceLocation> DeviceLocations => Set<DeviceLocation>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<DeviceLocation>().HasKey(x => x.DeviceId);
        model.Entity<AppUser>().HasIndex(x => x.Username).IsUnique();
        model.Entity<AppUser>().HasIndex(x => x.Email).IsUnique();
        model.Entity<GuardDevice>().HasIndex(x => x.DeviceCode).IsUnique();
        model.Entity<MemberAccess>().HasIndex(x => new { x.OwnerId, x.MemberUserId, x.DeviceId });
        model.Entity<OtpChallenge>().HasIndex(x => new { x.UserId, x.Purpose, x.ExpiresAt });
        model.Entity<AlarmEvent>().HasIndex(x => new { x.DeviceId, x.OccurredAt });
        model.Entity<Zone>().Property(x => x.Name).HasMaxLength(100);
        model.Entity<GuardDevice>().Property(x => x.Name).HasMaxLength(100);
        model.Entity<GuardDevice>().Property(x => x.DeviceCode).HasMaxLength(60);
        model.Entity<AppUser>().Property(x => x.Username).HasMaxLength(50);
        model.Entity<AppUser>().Property(x => x.Email).HasMaxLength(256);
    }
}
