namespace NguyenThanhTrung_SmartGuard_API.Models;

public record RegisterRequest(string Username, string Email, string Password);
public record VerifyEmailRequest(Guid ChallengeId, string Code);
public record LoginRequest(string Username, string Password);
public record VerifyLoginRequest(Guid ChallengeId, string Code);
public record ZoneRequest(string Name, string? Description);
public record DeviceRequest(string Name, string DeviceCode, string? Description, Guid? ZoneId, Guid? ConfigId, bool IsArmed);
public record ConfigRequest(string Name, int Sensitivity, int AlarmVolume, int DelaySeconds);
public record MemberRequest(string Email, Guid? DeviceId, bool CanAcknowledge);
public record MemberUpdateRequest(Guid? DeviceId, bool CanAcknowledge);
public record EventRequest(double MotionScore);
public record UserRoleRequest(string Role);
public record LocationUpdateRequest(double Latitude, double Longitude, double AccuracyMeters);
