using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

public sealed record Project(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name);

public sealed record UploadedLog(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("filename")] string Filename,
    [property: JsonPropertyName("duplicate")] bool Duplicate);

public sealed record Account(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("plan")] string Plan,
    [property: JsonPropertyName("planName")] string PlanName,
    [property: JsonPropertyName("limits")] AccountLimits Limits,
    [property: JsonPropertyName("usage")] AccountUsage Usage);

public sealed record AccountLimits(
    [property: JsonPropertyName("maxLogs")] int? MaxLogs,
    [property: JsonPropertyName("maxFileSizeMb")] int MaxFileSizeMb,
    [property: JsonPropertyName("maxFilesPerUpload")] int MaxFilesPerUpload);

public sealed record AccountUsage(
    [property: JsonPropertyName("logs")] int Logs);

// OpenRead is a factory so a retried request can re-open the file.
// ExternalId (your own id, e.g. a session id) makes a retried upload return the existing log.
public sealed record LogFile(
    string FileName, Func<Stream> OpenRead, string? Note = null, string? ExternalId = null);

public sealed class DatazapClient
{
    // No global timeout: callers bound each call with their CancellationToken
    private readonly HttpClient _http = new()
    {
        BaseAddress = new Uri("https://datazap.me/"),
        Timeout = Timeout.InfiniteTimeSpan,
    };
    private readonly ITokenStore _store;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public string ClientId { get; }
    // Custom scheme on mobile; null on desktop, where a loopback URI is built per attempt
    public string? RedirectUri { get; }

    public DatazapClient(string clientId, string? redirectUri, ITokenStore store)
    {
        ClientId = clientId;
        RedirectUri = redirectUri;
        _store = store;
    }

    public async Task<bool> IsConnectedAsync() => await _store.LoadAsync() is not null;

    // ---- Connect / disconnect (Steps 1 to 5) ----

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        var (verifier, challenge) = Pkce.Create();
        var state = Pkce.RandomState();

        // Mobile uses the fixed scheme; desktop builds a loopback URI with a port picked now.
        // The same string must go into the authorize URL and the token exchange.
        var redirectUri = RedirectUri ?? $"http://127.0.0.1:{FreeLoopbackPort()}/callback";
        var authorizeUrl = BuildAuthorizeUrl(ClientId, redirectUri, challenge, state);

        var code = RedirectUri is not null
            ? await RunConsentAsync(authorizeUrl, redirectUri, state, ct)
            : await RunConsentOnLoopbackAsync(authorizeUrl, redirectUri, state, ct);

        using var response = await _http.PostAsJsonAsync("api/integrations/token", new
        {
            grant_type = "authorization_code",
            code,
            client_id = ClientId,
            code_verifier = verifier,
            redirect_uri = redirectUri,
        }, ct);
        await _store.SaveAsync(await ReadTokensAsync(response, ct));
    }

    public async Task DisconnectAsync(CancellationToken ct = default)
    {
        // Serialize token mutations so a queued refresh cannot restore a disconnected session
        await _refreshLock.WaitAsync(ct);
        try
        {
            var tokens = await _store.LoadAsync();
            if (tokens is null) return;
            try
            {
                // Best effort: revoke server-side so it disappears from the user's settings
                using var response = await _http.PostAsJsonAsync(
                    "api/integrations/revoke",
                    new { token = tokens.RefreshToken, client_id = ClientId },
                    ct);
            }
            finally
            {
                await _store.ClearAsync();  // local disconnect succeeds even if revoke fails
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    // ---- API calls (Steps 7 to 9) ----

    public async Task<IReadOnlyList<Project>> GetProjectsAsync(CancellationToken ct = default)
    {
        using var response = await SendAsync(() =>
            new HttpRequestMessage(HttpMethod.Get, "api/v1/projects"), ct);
        await EnsureSuccessAsync(response, ct);
        return (await response.Content.ReadFromJsonAsync<ProjectsResponse>(ct))!.Projects;
    }

    public async Task<IReadOnlyList<UploadedLog>> UploadLogsAsync(
        IReadOnlyList<LogFile> files, string? projectId = null, CancellationToken ct = default)
    {
        // 20 is the API-wide ceiling; the plan may allow fewer (403 max_files_per_upload)
        if (files.Count is 0 or > 20)
            throw new ArgumentException("Send between 1 and 20 files per request.");

        using var response = await SendAsync(() =>
        {
            var form = new MultipartFormDataContent();
            foreach (var file in files)
            {
                var part = new StreamContent(file.OpenRead());
                part.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
                // Field name "files"; the file name must end in .csv
                form.Add(part, "files", file.FileName);
            }
            if (projectId is not null)
                form.Add(new StringContent(projectId), "projectId");
            if (files.Any(f => f.Note is not null))
            {
                var notes = JsonSerializer.Serialize(files.Select(f => f.Note).ToArray());
                form.Add(new StringContent(notes), "notes");
            }
            if (files.Any(f => f.ExternalId is not null))
            {
                var ids = JsonSerializer.Serialize(files.Select(f => f.ExternalId).ToArray());
                form.Add(new StringContent(ids), "externalIds");
            }
            return new HttpRequestMessage(HttpMethod.Post, "api/v1/logs/upload")
            {
                Content = form,
            };
        }, ct);

        await EnsureSuccessAsync(response, ct);
        return (await response.Content.ReadFromJsonAsync<UploadResponse>(ct))!.Logs;
    }

    // Optional (Step 9): plan, limits and usage for the connected account
    public async Task<Account> GetAccountAsync(CancellationToken ct = default)
    {
        using var response = await SendAsync(() =>
            new HttpRequestMessage(HttpMethod.Get, "api/v1/me"), ct);
        await EnsureSuccessAsync(response, ct);
        return (await response.Content.ReadFromJsonAsync<Account>(ct))!;
    }

    // ---- Token plumbing (Step 6) ----

    private async Task<HttpResponseMessage> SendAsync(
        Func<HttpRequestMessage> build, CancellationToken ct)
    {
        var tokens = await _store.LoadAsync()
            ?? throw new DatazapAuthException(
                "Not connected. Call ConnectAsync first.", null, 401);

        // Refresh a little early so a long upload never straddles the expiry
        if (tokens.ExpiresAt - DateTimeOffset.UtcNow < TimeSpan.FromMinutes(5))
            tokens = await RefreshAsync(tokens, ct);

        var response = await SendWithTokenAsync(build, tokens.AccessToken, ct);
        if (response.StatusCode != HttpStatusCode.Unauthorized) return response;

        // Rejected anyway (clock skew, revoked elsewhere): refresh once and retry once
        response.Dispose();
        tokens = await RefreshAsync(tokens, ct);
        response = await SendWithTokenAsync(build, tokens.AccessToken, ct);

        // Still 401 with a fresh token: the session is gone, make the caller reconnect
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            await _store.ClearAsync();
        return response;
    }

    private async Task<HttpResponseMessage> SendWithTokenAsync(
        Func<HttpRequestMessage> build, string accessToken, CancellationToken ct)
    {
        using var request = build();   // disposing the request closes the file streams
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _http.SendAsync(request, ct);
    }

    private async Task<StoredTokens> RefreshAsync(StoredTokens current, CancellationToken ct)
    {
        await _refreshLock.WaitAsync(ct);
        try
        {
            // Re-read under the lock. A disconnect that ran while we waited is final, even if
            // its revoke never reached the server; a refresh that ran is the live token pair.
            var latest = await _store.LoadAsync()
                ?? throw new DatazapAuthException(
                    "Not connected. Call ConnectAsync first.", null, 401);
            if (latest.RefreshToken != current.RefreshToken)
                return latest;

            using var response = await _http.PostAsJsonAsync("api/integrations/token", new
            {
                grant_type = "refresh_token",
                refresh_token = current.RefreshToken,
                client_id = ClientId,
            }, ct);

            if (!response.IsSuccessStatusCode)
            {
                // A proxy can answer a 5xx with HTML; that must still reach the retry path
                OAuthError? err = null;
                try { err = await response.Content.ReadFromJsonAsync<OAuthError>(ct); }
                catch (JsonException) { }

                // Only invalid_grant ends the session (disconnected or re-authorized)
                if (err?.Error == "invalid_grant")
                {
                    await _store.ClearAsync();
                    throw new DatazapAuthException(
                        $"Reconnect required ({err.Error}: {err.Description})",
                        err.Error, (int)response.StatusCode);
                }
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    throw new DatazapRateLimitException(
                        err?.Description ?? "Rate limited", RetryAfter(response));

                // 5xx, network hiccup at the edge, etc.: keep the stored tokens and try later
                throw new DatazapApiException(
                    (int)response.StatusCode,
                    err?.Description ?? err?.Error ?? response.ReasonPhrase
                        ?? "Refresh failed",
                    err?.Error);
            }

            var stored = await ReadTokensAsync(response, ct);
            await _store.SaveAsync(stored);
            return stored;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private static async Task<StoredTokens> ReadTokensAsync(
        HttpResponseMessage response, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            OAuthError? err = null;
            try { err = await response.Content.ReadFromJsonAsync<OAuthError>(ct); }
            catch (JsonException) { }
            throw new DatazapAuthException(
                $"{err?.Error ?? response.ReasonPhrase}: {err?.Description}",
                err?.Error, (int)response.StatusCode);
        }
        var t = (await response.Content.ReadFromJsonAsync<TokenResponse>(ct))!;
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(t.ExpiresIn);
        return new StoredTokens(t.AccessToken, t.RefreshToken, expiresAt);
    }

    private static async Task EnsureSuccessAsync(
        HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;

        ApiError? body = null;
        try { body = await response.Content.ReadFromJsonAsync<ApiError>(ct); }
        catch (JsonException) { }
        var message = body?.Error ?? response.ReasonPhrase ?? "Request failed";

        // Branch on the stable code, never on the English message
        throw response.StatusCode switch
        {
            HttpStatusCode.Unauthorized => new DatazapAuthException(message, body?.Code, 401),
            HttpStatusCode.Forbidden or HttpStatusCode.RequestEntityTooLarge =>
                new DatazapLimitException(
                    (int)response.StatusCode, message, body?.Code, body?.Filename),
            HttpStatusCode.TooManyRequests =>
                new DatazapRateLimitException(message, RetryAfter(response)),
            _ => new DatazapApiException((int)response.StatusCode, message, body?.Code),
        };
    }

    // Datazap sends Retry-After in seconds; the date form is handled for completeness
    private static TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header?.Delta is { } delta) return delta;
        if (header?.Date is { } date) return date - DateTimeOffset.UtcNow;
        return null;
    }

    private sealed record ProjectsResponse(
        [property: JsonPropertyName("projects")] List<Project> Projects);
    private sealed record UploadResponse(
        [property: JsonPropertyName("logs")] List<UploadedLog> Logs);
    private sealed record ApiError(
        [property: JsonPropertyName("error")] string Error,
        [property: JsonPropertyName("code")] string? Code,
        [property: JsonPropertyName("filename")] string? Filename);
}

public class DatazapApiException : Exception
{
    public int Status { get; }
    public string? Code { get; }
    public DatazapApiException(int status, string message, string? code = null) : base(message)
    {
        Status = status;
        Code = code;
    }
}

// Stored tokens are gone (or never existed): show the connect button.
// Status is the real HTTP status: 401 from the API, 400 from the token endpoint,
// 0 for consent-flow errors that never reached the server.
public sealed class DatazapAuthException : DatazapApiException
{
    public DatazapAuthException(string message, string? code = null, int status = 0)
        : base(status, message, code) { }
}

// 403 or 413: a plan limit, a missing scope, or an inactive app. Code says which.
public sealed class DatazapLimitException : DatazapApiException
{
    public string? Filename { get; }
    public DatazapLimitException(int status, string message, string? code, string? filename)
        : base(status, message, code)
    {
        Filename = filename;
    }
}

public sealed class DatazapRateLimitException : DatazapApiException
{
    public TimeSpan? RetryAfter { get; }
    public DatazapRateLimitException(string message, TimeSpan? retryAfter)
        : base(429, message, "rate_limited")
    {
        RetryAfter = retryAfter;
    }
}
