using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NguyenThanhTrung_SmartGuard_API.Models;

namespace NguyenThanhTrung_SmartGuard_API.Services;

public static class Security
{
    public static Guid UserId(ClaimsPrincipal principal)
    {
        var id = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(id, out var parsed) ? parsed : Guid.Empty;
    }

    public static string CreateJwt(AppUser user, IConfiguration config)
    {
        var key = config["Jwt:Key"] ?? throw new InvalidOperationException("Missing Jwt:Key");
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(JwtRegisteredClaimNames.Email, user.Email)
        };
        var token = new JwtSecurityToken(
            issuer: config["Jwt:Issuer"], audience: config["Jwt:Audience"],
            claims: claims, expires: DateTime.UtcNow.AddHours(8),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string GenerateOtp() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    // Not storing OTP in plaintext. ChallengeId is random and unique.
    public static string HashOtp(Guid challengeId, string otp, string secret)
    {
        var bytes = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes($"{challengeId:N}:{otp}"));
        return Convert.ToHexString(bytes);
    }

    public static bool VerifyOtp(OtpChallenge challenge, string otp, string secret)
    {
        if (otp.Length != 6 || !otp.All(char.IsAsciiDigit)) return false;
        var expected = Convert.FromHexString(challenge.CodeHash);
        var actual = Convert.FromHexString(HashOtp(challenge.Id, otp, secret));
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    public static async Task<string?> SendOtpAsync(
        string email, string otp, string purpose, IConfiguration config, IHostEnvironment env)
    {
        var host = config["Smtp:Host"];
        if (string.IsNullOrWhiteSpace(host))
        {
            if (env.IsDevelopment()) return otp; // ONLY local development; never in production.
            throw new InvalidOperationException("SMTP must be configured in production.");
        }
        using var smtp = new SmtpClient(host, config.GetValue<int>("Smtp:Port", 587))
        {
            EnableSsl = config.GetValue("Smtp:EnableSsl", true),
            Credentials = new NetworkCredential(config["Smtp:User"], config["Smtp:Password"])
        };
        var from = config["Smtp:From"] ?? throw new InvalidOperationException("Missing Smtp:From");
        using var message = new MailMessage(from, email)
        {
            Subject = purpose == "VerifyEmail" ? "SmartGuard - Xác minh email" : "SmartGuard - Mã đăng nhập",
            Body = $"Mã OTP SmartGuard của bạn là: {otp}. Mã có hiệu lực 5 phút. Không chia sẻ mã này."
        };
        await smtp.SendMailAsync(message);
        return null;
    }
}
