using System.Security.Cryptography;
using System.Text;

public static class Pkce
{
    public static (string Verifier, string Challenge) Create()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToHexString(bytes).ToLowerInvariant();
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    // Echoed back in the redirect; compare it to stop CSRF
    public static string RandomState() => Base64Url(RandomNumberGenerator.GetBytes(16));

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
