import { createServer } from 'node:http';
import { exec } from 'node:child_process';
import { platform } from 'node:process';
import { DatazapAuthError } from './errors.js';

// Opens a URL in the user's default browser. In Electron use shell.openExternal(url) instead.
export function openBrowser(url) {
  const cmd = platform === 'win32' ? `start "" "${url}"`
    : platform === 'darwin' ? `open "${url}"`
    : `xdg-open "${url}"`;
  exec(cmd);
}

// Starts a loopback listener on a free port and returns { port, waitForCode }.
// Call this first so the port is known before the authorize URL is built.
export function startLoopbackListener(expectedState, { signal } = {}) {
  let settle;
  const result = new Promise((resolve, reject) => { settle = { resolve, reject }; });

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname !== '/callback') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>Done. You can return to the app.</body></html>');

    const params = url.searchParams;
    // Check state first: an unsolicited callback must not even produce a "declined" message
    if (params.get('state') !== expectedState) {
      settle.reject(new DatazapAuthError('State mismatch. Discard this response.'));
    } else if (params.has('error')) {
      const error = params.get('error');
      settle.reject(new DatazapAuthError(error === 'access_denied'
        ? 'The user declined.'
        : params.get('error_description') ?? error));
    } else if (params.get('code')) {
      settle.resolve(params.get('code'));
    } else {
      settle.reject(new DatazapAuthError('No authorization code in the callback.'));
    }
  });

  // The caller's AbortSignal bounds how long we wait for the browser round trip
  const cancel = () => settle.reject(new DatazapAuthError('The authorization flow was cancelled.'));
  if (signal?.aborted) cancel();
  signal?.addEventListener('abort', cancel, { once: true });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        waitForCode: () => result.finally(() => server.close()),
      });
    });
  });
}
