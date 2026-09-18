import { stat } from 'node:fs/promises';
import { DatazapAuthError, DatazapRateLimitError, DatazapLimitError, DatazapApiError }
  from './datazap-client.js';

// Machine state the app acts on; the notification message is separate
export const Pause = Object.freeze({
  RECONNECT_REQUIRED: 'reconnect_required',
  LOG_LIMIT_REACHED: 'log_limit_reached',
  MISSING_SCOPE: 'missing_scope',
  APP_INACTIVE: 'app_inactive',
});

// queue, settings and notifyOnce are placeholders for your own storage, preferences and
// notification code. queue entries are { path, fileName, sessionId, note }.
// Set settings.pause = null after a successful reconnect and on app launch.
export async function drainQueue(datazap, queue, settings, notifyOnce, { maxBatches, signal }) {
  if (!settings.autoUploadEnabled || settings.pause) return;
  if (!await datazap.isConnected()) return;

  // Cached from /me by foreground code (daily, or when null). Without it: 3 files, 3 MB
  const limits = settings.cachedLimits ?? { maxLogs: null, maxFileSizeMb: 3, maxFilesPerUpload: 3 };

  const pause = async (reason, message, batch) => {
    settings.pause = reason;
    notifyOnce(message);
    await queue.requeue(batch);
  };

  for (let pass = 0; pass < maxBatches && !signal?.aborted; pass++) {
    let batch = await queue.take(limits.maxFilesPerUpload);
    if (batch.length === 0) return;

    // Missing, unreadable or oversized files never make it into a request; park them
    // one at a time with a reason so one bad entry cannot stop the whole queue
    const maxBytes = limits.maxFileSizeMb * 1024 * 1024;
    const valid = [];
    for (const entry of batch) {
      try {
        const info = await stat(entry.path);
        if (info.size > maxBytes) await queue.park(entry, `Over the ${limits.maxFileSizeMb} MB limit`);
        else valid.push(entry);
      } catch (err) {
        await queue.park(entry, err.code === 'ENOENT' ? 'The source log no longer exists.' : err.message);
      }
    }
    batch = valid;
    if (batch.length === 0) continue;

    try {
      const files = batch.map(q => ({
        fileName: q.fileName, path: q.path, note: q.note, externalId: q.sessionId,
      }));
      await datazap.uploadLogs(files, { projectId: settings.defaultProjectId, signal });
      await queue.remove(batch);   // a duplicate response is still success
    } catch (err) {
      if (err instanceof DatazapLimitError && err.code === 'file_too_large') {
        // The server named the file: park that one, the rest go back for the next pass
        const culprit = batch.find(q => q.fileName === err.filename);
        if (culprit) await queue.park(culprit, err.message);
        await queue.requeue(batch.filter(q => q !== culprit));
      } else if (err instanceof DatazapLimitError && err.code === 'max_files_per_upload') {
        // Plan changed under us. Drop the cache rather than calling /me here; the next pass refreshes it.
        settings.cachedLimits = null;
        await queue.requeue(batch);
        return;
      } else if (err instanceof DatazapLimitError && err.code === 'log_limit_reached') {
        await pause(Pause.LOG_LIMIT_REACHED, err.message, batch);
        return;
      } else if (err instanceof DatazapApiError && (err.code === 'missing_scope' || err.code === 'app_inactive')) {
        // Conditions of the connection, not of these files: keep them queued
        await pause(err.code === 'missing_scope' ? Pause.MISSING_SCOPE : Pause.APP_INACTIVE, err.message, batch);
        return;
      } else if (err instanceof DatazapApiError && err.code === 'invalid_project') {
        settings.defaultProjectId = null;    // project was deleted; use top level
        await queue.requeue(batch);
      } else if (err instanceof DatazapRateLimitError) {
        await queue.retryLater(batch, err.retryAfterMs ?? 60_000);
        return;
      } else if (err instanceof DatazapAuthError) {
        await pause(Pause.RECONNECT_REQUIRED, 'Reconnect Datazap to resume auto-upload.', batch);
        return;
      } else if (err.name === 'TypeError' || err.name === 'AbortError' || err.name === 'TimeoutError'
                 || (err instanceof DatazapApiError && err.status >= 500)) {
        // Offline, cancelled, or server trouble: exponential backoff
        await queue.retryLater(batch, queue.nextBackoff(batch));
        return;
      } else if (err instanceof DatazapApiError) {
        // Anything else is a problem with this request itself: park it for the user
        await queue.park(batch, err.message);
      } else if (err.code === 'ENOENT' || err.code === 'EACCES') {
        // A file changed after validation. Requeue; the per-file check on the next pass
        // parks the bad entry on its own and the rest go through.
        await queue.requeue(batch);
        return;
      } else {
        throw err;
      }
    }
  }
}
