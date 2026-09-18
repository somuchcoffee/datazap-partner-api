using System.Net.Http.Json;
using System.Text.Json.Serialization;

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")]  public string AccessToken { get; set; } = "";
    [JsonPropertyName("refresh_token")] public string RefreshToken { get; set; } = "";
    [JsonPropertyName("token_type")]    public string TokenType { get; set; } = "Bearer";
    [JsonPropertyName("expires_in")]    public int ExpiresIn { get; set; }
    [JsonPropertyName("scope")]         public string Scope { get; set; } = "";
}

public sealed class OAuthError
{
    [JsonPropertyName("error")]             public string Error { get; set; } = "";
    [JsonPropertyName("error_description")] public string? Description { get; set; }
}

var tokenUrl = "https://datazap.me/api/integrations/token";
using var response = await http.PostAsJsonAsync(tokenUrl, new
{
    grant_type = "authorization_code",
    code,                       // from the callback
    client_id = clientId,
    code_verifier = verifier,   // from Pkce.Create(), same run as the challenge
    redirect_uri = redirectUri, // identical to the one in the authorize URL
});

if (!response.IsSuccessStatusCode)
{
    var err = await response.Content.ReadFromJsonAsync<OAuthError>();
    throw new DatazapAuthException($"{err?.Error}: {err?.Description}");
}
var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>();
