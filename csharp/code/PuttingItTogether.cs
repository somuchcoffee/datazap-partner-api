// Desktop apps pass null as the redirect URI and get a loopback port per attempt
var datazap = new DatazapClient(
    ClientId, "com.yourcompany.yourapp://datazap/callback", new SecureTokenStore());

// Bound the whole operation; uploads on cellular can be slow
using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));

try
{
    if (!await datazap.IsConnectedAsync())
        await datazap.ConnectAsync(cts.Token);   // opens the browser, returns on approval

    var projects = await datazap.GetProjectsAsync(cts.Token);
    var target = projects.FirstOrDefault(p => p.Name == "My E30 Build")?.Id;

    var uploaded = await datazap.UploadLogsAsync(new[]
    {
        new LogFile("2026-09-17_pull_3rd.csv", () => File.OpenRead(path3rd), "3rd gear pull"),
        new LogFile("2026-09-17_pull_4th.csv", () => File.OpenRead(path4th), "4th gear pull"),
    }, projectId: target, ct: cts.Token);

    // Retried files come back with Duplicate = true and were not created again
    var newCount = uploaded.Count(log => !log.Duplicate);
    ShowToast(newCount == 0
        ? "These logs are already in Datazap"
        : $"Uploaded {newCount} logs to Datazap");
}
catch (DatazapAuthException)
{
    ShowConnectButton();      // tokens were cleared; the user needs to authorize again
}
catch (DatazapRateLimitException ex)
{
    ScheduleRetry(ex.RetryAfter ?? TimeSpan.FromSeconds(10));
}
catch (DatazapLimitException ex)
{
    ShowMessage(ex.Message);  // e.g. "Log limit reached. Your free plan allows 100 logs."
}
catch (DatazapApiException ex)
{
    ShowMessage($"Datazap error {ex.Status}: {ex.Message}");
}
catch (Exception ex) when (ex is HttpRequestException || ex is OperationCanceledException)
{
    ShowMessage("Could not reach Datazap. Check your connection and try again.");
}
