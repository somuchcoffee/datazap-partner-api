public static Uri BuildAuthorizeUrl(
    string clientId, string redirectUri, string codeChallenge, string state)
{
    var query = new Dictionary<string, string>
    {
        ["response_type"] = "code",
        ["client_id"] = clientId,
        ["redirect_uri"] = redirectUri,
        ["scope"] = "logs:write projects:read",
        ["code_challenge"] = codeChallenge,
        ["code_challenge_method"] = "S256",
        ["state"] = state,
    };
    var qs = string.Join("&", query.Select(kv => $"{Enc(kv.Key)}={Enc(kv.Value)}"));
    return new Uri($"https://datazap.me/integrations/authorize?{qs}");

    static string Enc(string value) => Uri.EscapeDataString(value);
}
