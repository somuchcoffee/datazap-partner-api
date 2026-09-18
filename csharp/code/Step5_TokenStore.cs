public sealed record StoredTokens(
    string AccessToken, string RefreshToken, DateTimeOffset ExpiresAt);

public interface ITokenStore
{
    Task<StoredTokens?> LoadAsync();
    Task SaveAsync(StoredTokens tokens);
    Task ClearAsync();
}

// MAUI implementation
public sealed class SecureTokenStore : ITokenStore
{
    private const string Key = "datazap_tokens";

    public async Task<StoredTokens?> LoadAsync()
    {
        var json = await SecureStorage.Default.GetAsync(Key);
        return json is null ? null : JsonSerializer.Deserialize<StoredTokens>(json);
    }

    public Task SaveAsync(StoredTokens tokens) =>
        SecureStorage.Default.SetAsync(Key, JsonSerializer.Serialize(tokens));

    public Task ClearAsync()
    {
        SecureStorage.Default.Remove(Key);
        return Task.CompletedTask;
    }
}
