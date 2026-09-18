import { DatazapClient, DatazapAuthError, DatazapRateLimitError, DatazapLimitError, DatazapApiError }
  from './datazap-client.js';

const datazap = new DatazapClient(CLIENT_ID, tokenStore);

// Bound the whole operation; uploads on slow links can take a while
const signal = AbortSignal.timeout(10 * 60 * 1000);

try {
  if (!await datazap.isConnected())
    await datazap.connect({ signal });   // opens the browser, returns on approval

  const projects = await datazap.getProjects({ signal });
  const target = projects.find(p => p.name === 'My E30 Build')?.id;

  const result = await datazap.uploadLogs([
    { fileName: '2026-09-17_pull_3rd.csv', path: path3rd, note: '3rd gear pull' },
    { fileName: '2026-09-17_pull_4th.csv', path: path4th, note: '4th gear pull' },
  ], { projectId: target, signal });

  // Retried files come back with duplicate: true and were not created again
  showToast(result.uploadedCount === 0
    ? 'These logs are already in Datazap'
    : `Uploaded ${result.uploadedCount} logs to Datazap`);
} catch (err) {
  if (err instanceof DatazapAuthError) {
    showConnectButton();      // tokens were cleared; the user needs to authorize again
  } else if (err instanceof DatazapRateLimitError) {
    scheduleRetry(err.retryAfterMs ?? 10_000);
  } else if (err instanceof DatazapLimitError) {
    showMessage(err.message);  // e.g. "Log limit reached. Your free plan allows 100 logs."
  } else if (err instanceof DatazapApiError) {
    showMessage(`Datazap error ${err.status}: ${err.message}`);
  } else if (err.name === 'TypeError' || err.name === 'AbortError' || err.name === 'TimeoutError') {
    // fetch throws TypeError when the network is down; AbortSignal.timeout throws TimeoutError
    showMessage('Could not reach Datazap. Check your connection and try again.');
  } else {
    throw err;
  }
}
