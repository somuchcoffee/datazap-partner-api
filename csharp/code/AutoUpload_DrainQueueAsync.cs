public enum AutoUploadPause
{
    None, ReconnectRequired, LogLimitReached, MissingScope, AppInactive
}

// Set Settings.Pause = AutoUploadPause.None after a reconnect and on app foreground
public async Task DrainQueueAsync(
    DatazapClient datazap, IUploadQueue queue, int maxBatches, CancellationToken ct)
{
    if (!Settings.AutoUploadEnabled || Settings.Pause != AutoUploadPause.None) return;
    if (!await datazap.IsConnectedAsync()) return;

    var onWifi = Connectivity.Current.ConnectionProfiles.Contains(ConnectionProfile.WiFi);
    if (Settings.WifiOnly && !onWifi) return;

    // Cached from /me by foreground code (daily, or when null). Without it: 3 files, 3 MB
    var limits = Settings.CachedLimits ?? new AccountLimits(null, 3, 3);

    for (var pass = 0; pass < maxBatches && !ct.IsCancellationRequested; pass++)
    {
        var batch = await queue.TakeAsync(limits.MaxFilesPerUpload);
        if (batch.Count == 0) return;

        // Missing, unreadable or oversized files never make it into a request; park them
        // one at a time with a reason so one bad entry cannot stop the whole queue
        var maxBytes = limits.MaxFileSizeMb * 1024L * 1024;
        var valid = new List<QueueEntry>();
        foreach (var q in batch)
        {
            try
            {
                var info = new FileInfo(q.Path);
                if (!info.Exists)
                    await queue.ParkAsync(q, "The source log no longer exists.");
                else if (info.Length > maxBytes)
                    await queue.ParkAsync(q, $"Over the {limits.MaxFileSizeMb} MB limit");
                else
                    valid.Add(q);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                await queue.ParkAsync(q, ex.Message);
            }
        }
        batch = valid;
        if (batch.Count == 0) continue;

        try
        {
            var files = batch
                .Select(q => new LogFile(
                    q.FileName, () => File.OpenRead(q.Path), q.Note, q.SessionId))
                .ToList();

            await datazap.UploadLogsAsync(files, Settings.DefaultProjectId, ct);
            await queue.RemoveAsync(batch);   // a duplicate response is still success
        }
        catch (DatazapLimitException ex) when (ex.Code == "file_too_large")
        {
            // The server named the file: park that one, the rest go back for the next pass
            var culprit = batch.FirstOrDefault(q => q.FileName == ex.Filename);
            if (culprit is not null) await queue.ParkAsync(culprit, ex.Message);
            await queue.RequeueAsync(batch.Where(q => q != culprit));
        }
        catch (DatazapLimitException ex) when (ex.Code == "max_files_per_upload")
        {
            // Plan changed under us. Drop the cache rather than calling /me here: a
            // network call inside a catch would escape the handlers below.
            Settings.CachedLimits = null;
            await queue.RequeueAsync(batch);
            return;
        }
        catch (DatazapLimitException ex) when (ex.Code == "log_limit_reached")
        {
            await PauseAsync(AutoUploadPause.LogLimitReached, ex.Message, batch);
            return;
        }
        catch (DatazapApiException ex) when (ex.Code is "missing_scope" or "app_inactive")
        {
            // Conditions of the connection, not of these files: keep them queued
            var reason = ex.Code == "missing_scope"
                ? AutoUploadPause.MissingScope
                : AutoUploadPause.AppInactive;
            await PauseAsync(reason, ex.Message, batch);
            return;
        }
        catch (DatazapApiException ex) when (ex.Code == "invalid_project")
        {
            Settings.DefaultProjectId = null;    // project was deleted; use top level
            await queue.RequeueAsync(batch);
        }
        catch (DatazapRateLimitException ex)
        {
            await queue.RetryLaterAsync(batch, ex.RetryAfter ?? TimeSpan.FromMinutes(1));
            return;
        }
        catch (DatazapAuthException)
        {
            await PauseAsync(AutoUploadPause.ReconnectRequired,
                "Reconnect Datazap to resume auto-upload.", batch);
            return;
        }
        catch (Exception ex) when (ex is HttpRequestException
                                   || ex is OperationCanceledException
                                   || ex is DatazapApiException { Status: >= 500 })
        {
            // Offline, out of background time, or server trouble: exponential backoff
            await queue.RetryLaterAsync(batch, queue.NextBackoff(batch));
            return;
        }
        catch (DatazapApiException ex)
        {
            // Anything else is a problem with this request itself: park it for the user
            await queue.ParkAsync(batch, ex.Message);
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            // A file changed after validation. Requeue; the per-file check on the next pass
            // parks the bad entry on its own and the rest go through.
            await queue.RequeueAsync(batch);
            return;
        }
    }

    // The enum is the state the app acts on; the message is only for the notification
    async Task PauseAsync(
        AutoUploadPause reason, string message, IEnumerable<QueueEntry> batch)
    {
        Settings.Pause = reason;
        NotifyOnce(message);
        await queue.RequeueAsync(batch);
    }
}
