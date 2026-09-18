public async Task<string> RunConsentAsync(
    Uri authorizeUrl, string redirectUri, string state, CancellationToken ct)
{
    WebAuthenticatorResult result;
    try
    {
        // WaitAsync lets the caller's token bound the browser round trip
        result = await WebAuthenticator.Default
            .AuthenticateAsync(authorizeUrl, new Uri(redirectUri))
            .WaitAsync(ct);
    }
    catch (OperationCanceledException)
    {
        // The user closed the browser, or the caller's token fired
        throw new DatazapAuthException("The authorization flow was cancelled.");
    }

    // Check state first: an unsolicited callback must not even produce a "declined" message
    if (result.Get("state") != state)
        throw new DatazapAuthException("State mismatch. Discard this response.");

    // The user tapped Deny: the redirect carries error=access_denied instead of a code
    if (result.Properties.TryGetValue("error", out var error))
        throw new DatazapAuthException(error == "access_denied"
            ? "The user declined."
            : result.Get("error_description") ?? error);

    return result.Get("code")
        ?? throw new DatazapAuthException("No authorization code in the callback.");
}
