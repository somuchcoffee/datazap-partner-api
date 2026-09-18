# Datazap Partner API · JavaScript Integration Guide

Node.js 20+ and Electron · OAuth 2.0 Authorization Code + PKCE · `fetch` · no dependencies

The code in this guide is also in [`code/`](code/) as plain files, one per step, so you can copy a whole module
without pulling it out of a document. They are the same snippets that appear inline below.

## Introduction

Datazap lets your app upload data logs straight into a user's Datazap account. The user approves your app once on a Datazap consent screen, your app receives an access token, and from then on it can upload CSV logs and list the user's projects on their behalf. This guide is long because it includes a complete client and handles the edge cases; the integration itself is small.

### The process in three parts

1. **Connect once.** Your app opens the Datazap consent page in the system browser. The user signs in and taps *Authorize*. Your app receives an access token and a refresh token and stores them securely. Steps 1 to 6.
2. **Upload logs.** Your app sends one or more CSV files to a single endpoint with that token, optionally into a project the user picked from a list. Steps 7 to 9.
3. **Stay connected.** The access token lasts 24 hours and the client class in this guide refreshes it for you. The user can disconnect your app from their Datazap settings at any time, and your app finds out on its next call. Step 6 and the Error reference.

### Two ways to use it

- **Send to Datazap.** Add a button to a saved log or a multi-select of logs. The user can optionally choose a project and add notes, then taps Send. It's the simplest integration and works well on its own.
- **Auto-upload.** An opt-in setting that queues each completed logging session and uploads it in the background. Once enabled, logs appear in Datazap automatically, with no extra steps from the user. It uses the same API, with additional handling for queueing, retries, connectivity, and plan limits.

Both patterns are covered with code under *Integration patterns* after the shared client implementation. Everything before that applies to both.

### How this guide is organized

| Section | What it covers |
|---|---|
| Steps 1 to 6 | Connecting: PKCE, the consent screen via a loopback redirect, token exchange, secure storage, and a reusable `DatazapClient` class that refreshes and retries |
| Steps 7 to 9 | The API: list projects, upload logs, and an optional plan and usage call |
| Putting it together | A complete connect, list, upload example with error handling |
| Integration patterns | Send to Datazap and Auto-upload, including a background queue drain |
| Reference | Error codes, a testing checklist, confidential clients, and what to send us to go live |

## Overview

Datazap uses OAuth 2.0 Authorization Code with PKCE. The authorization flow follows the standard protocol, with one Datazap-specific difference: the token endpoint accepts a JSON body rather than `application/x-www-form-urlencoded`, so libraries that assume form-encoded token requests may need a custom token exchange. Everything in this guide is written against the built-in `fetch`, `FormData` and `node:crypto`, so it drops into a Node 20+ or Electron project with no packages. One caveat: `fs.openAsBlob()`, used to stream files into `FormData` in Step 6, is available in Node 20 but marked experimental there; it is stable in newer releases.

**Which JavaScript this is for.** The code targets a desktop app (Electron, or a Node CLI or service running on the user's machine), where you can listen on a loopback port for the OAuth redirect and read log files from disk. A browser-only web app can do neither; see *Browser-only apps* at the end.

### Getting set up

You send us the redirect URIs your app will use (loopback URLs, see Step 3) and we send back a `client_id`, the public identifier for your app. The full checklist is under *Going live*.

There is no client secret. Your app is registered as a *public client*: a binary on a user's machine cannot keep a secret, so PKCE and the registered redirect URI are what protect the exchange, and the token endpoint takes the `client_id` alone. See *Confidential clients* at the end if your integration runs on a server instead.

### Quick reference

| Item | Value |
|---|---|
| Consent page (open in the system browser) | `https://datazap.me/integrations/authorize` |
| Token endpoint (JSON body) | `POST https://datazap.me/api/integrations/token` |
| Revoke endpoint (JSON body) | `POST https://datazap.me/api/integrations/revoke` |
| List projects | `GET https://datazap.me/api/v1/projects` |
| Upload logs (multipart) | `POST https://datazap.me/api/v1/logs/upload` |
| Plan and usage (optional) | `GET https://datazap.me/api/v1/me` |
| Access token lifetime | 24 hours (`expires_in` is in seconds) |
| Refresh token | Rotates on every refresh. Stays valid until the user disconnects or re-authorizes. |
| Client type | Public: PKCE only, no client secret |
| PKCE | Required, `S256` only |
| Redirect URI matching | Exact, except loopback `http://127.0.0.1` URIs match on any port |
| Rate limit | 60 requests per minute per access token on `/api/v1/*` |
| Max files per upload request | Free 3, Pro 10, Tuner 20, by the user's plan (see Step 8). `.csv` only. |
| Error responses | JSON with a readable `error` and a stable `code` (see Error reference) |

> **Two things that trip up OAuth libraries**
> The token endpoint takes a JSON body, not `application/x-www-form-urlencoded`. And a custom-scheme `redirect_uri` must match a registered URI character for character; only loopback URIs get a free port.

## How the flow fits together

1. Generate a PKCE verifier and challenge plus a random `state`.
2. Open the consent page in the system browser with your `client_id`, redirect URI, scopes and challenge.
3. The user signs in if needed and taps *Authorize*. Datazap redirects to your redirect URI with `code` and `state`.
4. Exchange the code (plus the PKCE verifier) for an access token and a refresh token.
5. Call the API with `Authorization: Bearer <access_token>`. Refresh when you get a 401.

## Step 1 · PKCE helper

The verifier is 32 random bytes as lowercase hex (64 characters, inside the 43 to 128 range PKCE allows). The challenge is the SHA-256 of the verifier's ASCII bytes, base64url encoded without padding. Datazap hashes the verifier string exactly as sent, so keep it as plain ASCII.

*pkce.js*

```javascript
import { createHash, randomBytes } from 'node:crypto';

export function createPkce() {
  const verifier = randomBytes(32).toString('hex');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return { verifier, challenge };
}

// Echoed back in the redirect; compare it to stop CSRF
export function randomState() {
  return randomBytes(16).toString('base64url');
}
```

## Step 2 · Build the authorization URL

`scope` is the permission list the consent screen shows the user. Send both, space separated: `logs:write` to upload logs and `projects:read` to list projects so the user can pick where uploads go. `URLSearchParams` handles the encoding.

*authorize-url.js*

```javascript
export function buildAuthorizeUrl(clientId, redirectUri, codeChallenge, state) {
  const url = new URL('https://datazap.me/integrations/authorize');
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'logs:write projects:read',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  }).toString();
  return url;
}
```

If the user is not signed in to Datazap they are sent to the login page and returned to the consent screen afterwards. The consent screen shows your app name, logo, description and the requested permissions.

## Step 3 · Open the browser and receive the callback

Always use the system browser, never an embedded webview or a `BrowserWindow`. The app listens on a loopback port and opens the default browser. Register `http://127.0.0.1/callback` with us once, without a port: loopback redirect URIs match on any port, so the app can bind whichever port is free at runtime and put that port in the authorization request.

Binding port `0` asks the OS for a free port and keeps it, so there is no window for another process to take it. Because the port changes per attempt, the redirect URI is built inside `connect()` (Step 6) rather than fixed up front.

First, the error types the rest of the guide throws. They carry the HTTP status and Datazap's stable error `code` so callers can branch without parsing messages.

*errors.js*

```javascript
export class DatazapApiError extends Error {
  constructor(status, message, code = null) {
    super(message);
    this.name = 'DatazapApiError';
    this.status = status;
    this.code = code;
  }
}

// Stored tokens are gone (or never existed): show the connect button.
// status is the real HTTP status: 401 from the API, 400 from the token endpoint,
// 0 for consent-flow errors that never reached the server.
export class DatazapAuthError extends DatazapApiError {
  constructor(message, code = null, status = 0) {
    super(status, message, code);
    this.name = 'DatazapAuthError';
  }
}

// 403 or 413: a plan limit, a missing scope, or an inactive app. code says which.
export class DatazapLimitError extends DatazapApiError {
  constructor(status, message, code, filename = null) {
    super(status, message, code);
    this.name = 'DatazapLimitError';
    this.filename = filename;
  }
}

export class DatazapRateLimitError extends DatazapApiError {
  constructor(message, retryAfterMs) {
    super(429, message, 'rate_limited');
    this.name = 'DatazapRateLimitError';
    this.retryAfterMs = retryAfterMs;
  }
}
```

*consent.js*

```javascript
import { createServer } from 'node:http';
import { exec } from 'node:child_process';
import { platform } from 'node:process';
import { DatazapAuthError } from './errors.js';

// Plain-Node fallback for opening the default browser. In Electron, use shell.openExternal(url)
// from the main process instead; it is the supported path and needs no shell commands.
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
```

## Step 4 · Exchange the code for tokens

One JSON POST with no client secret. The response carries both tokens; the access token expires in 24 hours. Errors come back as `{ "error": "invalid_grant", "error_description": "..." }` with a 400.

```javascript
const response = await fetch('https://datazap.me/api/integrations/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,                        // from the callback
    client_id: clientId,
    code_verifier: verifier,     // from createPkce(), same run as the challenge
    redirect_uri: redirectUri,   // identical to the one in the authorize URL
  }),
});

if (!response.ok) {
  const err = await response.json().catch(() => null);
  throw new DatazapAuthError(`${err?.error}: ${err?.error_description}`);   // from errors.js
}
const tokens = await response.json();
// { access_token, refresh_token, token_type: "Bearer", expires_in: 86400, scope: "logs:write projects:read" }
```

## Step 5 · Store the tokens

Persist the access token, the refresh token and the computed expiry. Never log tokens, and never keep them in `localStorage` in a renderer process. In Electron, keep token storage in the main process and use `safeStorage` to encrypt them, writing the ciphertext to `app.getPath('userData')`. On macOS and Windows it is OS-backed (Keychain, DPAPI); on Linux, check `safeStorage.getSelectedStorageBackend()` and treat `basic_text` as no protection at all. In a plain Node desktop app, use an actively maintained credential-store package for the target OS. The file store below is for development only.

*token-store.js*

```javascript
import { readFile, writeFile, unlink } from 'node:fs/promises';

// Any object with load(), save(tokens) and clear() works as a token store.
// tokens is { accessToken, refreshToken, expiresAt } with expiresAt as epoch milliseconds.

// Electron, main process only: encrypted via safeStorage (verify the backend on Linux)
export class SafeStorageTokenStore {
  constructor(safeStorage, filePath) {
    this.safeStorage = safeStorage;
    this.filePath = filePath;   // e.g. path.join(app.getPath('userData'), 'datazap-tokens.bin')
  }

  async load() {
    try {
      const encrypted = await readFile(this.filePath);
      return JSON.parse(this.safeStorage.decryptString(encrypted));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async save(tokens) {
    await writeFile(this.filePath, this.safeStorage.encryptString(JSON.stringify(tokens)));
  }

  async clear() {
    await unlink(this.filePath).catch(err => { if (err.code !== 'ENOENT') throw err; });
  }
}

// Development only: plaintext JSON on disk
export class FileTokenStore {
  constructor(filePath) { this.filePath = filePath; }
  async load() {
    try { return JSON.parse(await readFile(this.filePath, 'utf8')); }
    catch (err) { if (err.code === 'ENOENT') return null; throw err; }
  }
  async save(tokens) { await writeFile(this.filePath, JSON.stringify(tokens)); }
  async clear() { await unlink(this.filePath).catch(err => { if (err.code !== 'ENOENT') throw err; }); }
}
```

## Step 6 · A client that refreshes and retries

The class below covers token exchange, refresh, and the Datazap API calls. A few details matter and are easy to get wrong, so they are built in:

- **Refresh tokens rotate.** Every refresh returns a new refresh token and invalidates the old one. Two refreshes racing each other leave you with a dead session, so refreshes are serialized through a single in-flight promise and the store is re-read after the wait. Keep one `DatazapClient` per app; the lock only coordinates calls through the same instance, so a main process and a worker must not each have one.
- **Persist the refresh response before anything else.** If the network drops after Datazap rotated the tokens but before your app stored the new pair, that installation has to reconnect. The client saves first and returns second for that reason.
- **Only `invalid_grant` ends the session.** A refresh that fails with a 5xx or a 429 is a temporary problem and keeps the stored tokens. Only `invalid_grant` (the user disconnected, or authorized again elsewhere) clears them.
- **Requests are built by a factory.** A `FormData` holding file streams can only be sent once, so a retry after a 401 rebuilds the body and reopens the files.
- **Every call takes an `AbortSignal`.** `fetch` has no default timeout, which is right for large uploads on slow links, but it means you must bound calls yourself. `AbortSignal.timeout(ms)` is the simplest way. One consequence of the shared refresh: the caller that starts it also supplies its signal, so if that caller is cancelled, other calls waiting on the same refresh fail too. Give background work a generous bound rather than a tight one.

*datazap-client.js*

```javascript
import { openAsBlob } from 'node:fs';
import { createPkce, randomState } from './pkce.js';
import { buildAuthorizeUrl } from './authorize-url.js';
import { openBrowser, startLoopbackListener } from './consent.js';
import { DatazapApiError, DatazapAuthError, DatazapLimitError, DatazapRateLimitError } from './errors.js';

export { DatazapApiError, DatazapAuthError, DatazapLimitError, DatazapRateLimitError };

const BASE = 'https://datazap.me/';

// { fileName, path, note?, externalId? }. externalId (your own id, e.g. a session id)
// makes a retried upload return the existing log instead of a copy.
export class DatazapClient {
  #store;
  #refreshing = null;     // in-flight refresh promise, so concurrent callers share one refresh
  #disconnecting = false; // blocks a new refresh from starting while disconnect() runs

  constructor(clientId, store) {
    this.clientId = clientId;
    this.#store = store;
  }

  async isConnected() {
    return (await this.#store.load()) !== null;
  }

  // ---- Connect / disconnect (Steps 1 to 5) ----

  async connect({ signal } = {}) {
    const { verifier, challenge } = createPkce();
    const state = randomState();

    // The listener picks the port, so the redirect URI is only known now.
    // The same string must go into the authorize URL and the token exchange.
    const { port, waitForCode } = await startLoopbackListener(state, { signal });
    const redirectUri = `http://127.0.0.1:${port}/callback`;
    openBrowser(buildAuthorizeUrl(this.clientId, redirectUri, challenge, state).toString());
    const code = await waitForCode();

    const response = await fetch(new URL('api/integrations/token', BASE), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: this.clientId,
        code_verifier: verifier,
        redirect_uri: redirectUri,
      }),
      signal,
    });
    await this.#store.save(await DatazapClient.#readTokens(response));
  }

  async disconnect({ signal } = {}) {
    // Refuse new refreshes, then wait out any in-flight one, so nothing can re-save
    // a rotated token pair after we clear the store
    this.#disconnecting = true;
    try {
      await this.#refreshing?.catch(() => {});
      const tokens = await this.#store.load();
      if (!tokens) return;
      try {
        // Best effort: revoke server-side so it disappears from the user's settings
        await fetch(new URL('api/integrations/revoke', BASE), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: tokens.refreshToken, client_id: this.clientId }),
          signal,
        });
      } finally {
        await this.#store.clear();   // local disconnect succeeds even if revoke fails
      }
    } finally {
      this.#disconnecting = false;
    }
  }

  // ---- API calls (Steps 7 to 9) ----

  async getProjects({ signal } = {}) {
    const response = await this.#send(() => ({ path: 'api/v1/projects' }), signal);
    await DatazapClient.#ensureSuccess(response);
    return (await response.json()).projects;
  }

  async uploadLogs(files, { projectId = null, signal } = {}) {
    // 20 is the API-wide ceiling; the plan may allow fewer (403 max_files_per_upload)
    if (files.length === 0 || files.length > 20)
      throw new RangeError('Send between 1 and 20 files per request.');

    const response = await this.#send(async () => {
      const form = new FormData();
      for (const file of files) {
        // Field name "files"; the file name must end in .csv. openAsBlob streams from disk.
        form.append('files', await openAsBlob(file.path, { type: 'text/csv' }), file.fileName);
      }
      if (projectId) form.append('projectId', projectId);
      if (files.some(f => f.note != null))
        form.append('notes', JSON.stringify(files.map(f => f.note ?? null)));
      if (files.some(f => f.externalId != null))
        form.append('externalIds', JSON.stringify(files.map(f => f.externalId ?? null)));
      return { path: 'api/v1/logs/upload', method: 'POST', body: form };
    }, signal);

    await DatazapClient.#ensureSuccess(response);
    return await response.json();   // { success, uploadedCount, logs: [{ id, filename, duplicate }] }
  }

  // Optional (Step 9): plan, limits and usage for the connected account
  async getAccount({ signal } = {}) {
    const response = await this.#send(() => ({ path: 'api/v1/me' }), signal);
    await DatazapClient.#ensureSuccess(response);
    return await response.json();
  }

  // ---- Token plumbing (Step 6) ----

  async #send(build, signal) {
    let tokens = await this.#store.load();
    if (!tokens) throw new DatazapAuthError('Not connected. Call connect() first.', null, 401);

    // Refresh a little early so a long upload never straddles the expiry
    if (tokens.expiresAt - Date.now() < 5 * 60 * 1000)
      tokens = await this.#refresh(tokens, signal);

    let response = await this.#sendWithToken(build, tokens.accessToken, signal);
    if (response.status !== 401) return response;

    // Rejected anyway (clock skew, revoked elsewhere): refresh once and retry once.
    // Cancel the discarded body first so its connection goes back to the pool.
    await response.body?.cancel();
    tokens = await this.#refresh(tokens, signal);
    response = await this.#sendWithToken(build, tokens.accessToken, signal);

    // Still 401 with a fresh token: the session is gone, make the caller reconnect
    if (response.status === 401) await this.#store.clear();
    return response;
  }

  async #sendWithToken(build, accessToken, signal) {
    const { path, method = 'GET', body } = await build();   // rebuilt per attempt: file streams are single-use
    return fetch(new URL(path, BASE), {
      method,
      headers: { Authorization: `Bearer ${accessToken}` },
      body,
      signal,
    });
  }

  // Serialized: concurrent callers await the same in-flight refresh instead of racing
  #refresh(current, signal) {
    if (this.#disconnecting)
      return Promise.reject(new DatazapAuthError('Not connected. Call connect() first.', null, 401));
    this.#refreshing ??= this.#doRefresh(current, signal).finally(() => { this.#refreshing = null; });
    return this.#refreshing;
  }

  async #doRefresh(current, signal) {
    // Re-read the store. A disconnect that ran in the meantime is final, even if its revoke
    // never reached the server; a refresh that ran is the live token pair.
    const latest = await this.#store.load();
    if (!latest) throw new DatazapAuthError('Not connected. Call connect() first.', null, 401);
    if (latest.refreshToken !== current.refreshToken) return latest;

    const response = await fetch(new URL('api/integrations/token', BASE), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: current.refreshToken,
        client_id: this.clientId,
      }),
      signal,
    });

    if (!response.ok) {
      // A proxy can answer a 5xx with HTML; that must still reach the retry path
      const err = await response.json().catch(() => null);

      // Only invalid_grant ends the session (disconnected or re-authorized)
      if (err?.error === 'invalid_grant') {
        await this.#store.clear();
        throw new DatazapAuthError(
          `Reconnect required (${err.error}: ${err.error_description})`, err.error, response.status);
      }
      if (response.status === 429)
        throw new DatazapRateLimitError(err?.error_description ?? 'Rate limited', retryAfter(response));

      // 5xx, network hiccup at the edge, etc.: keep the stored tokens and try later
      throw new DatazapApiError(
        response.status, err?.error_description ?? err?.error ?? response.statusText ?? 'Refresh failed', err?.error);
    }

    const stored = await DatazapClient.#readTokens(response);
    await this.#store.save(stored);
    return stored;
  }

  static async #readTokens(response) {
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new DatazapAuthError(
        `${err?.error ?? response.statusText}: ${err?.error_description}`, err?.error, response.status);
    }
    const t = await response.json();
    return {
      accessToken: t.access_token,
      refreshToken: t.refresh_token,
      expiresAt: Date.now() + t.expires_in * 1000,
    };
  }

  static async #ensureSuccess(response) {
    if (response.ok) return;

    const body = await response.json().catch(() => null);
    const message = body?.error ?? response.statusText ?? 'Request failed';

    // Branch on the stable code, never on the English message
    switch (response.status) {
      case 401: throw new DatazapAuthError(message, body?.code, 401);
      case 403:
      case 413: throw new DatazapLimitError(response.status, message, body?.code, body?.filename);
      case 429: throw new DatazapRateLimitError(message, retryAfter(response));
      default: throw new DatazapApiError(response.status, message, body?.code);
    }
  }
}

// Datazap sends Retry-After in seconds; the date form is handled for completeness.
// Returns milliseconds, or null.
function retryAfter(response) {
  const header = response.headers.get('Retry-After');
  if (!header) return null;
  const seconds = Number(header);
  if (!Number.isNaN(seconds)) return seconds * 1000;
  const date = Date.parse(header);
  return Number.isNaN(date) ? null : Math.max(0, date - Date.now());
}
```

## Step 7 · List projects

Projects are the folders a user organizes logs into. Offer them as the upload destination; uploading without a `projectId` is also fine and puts the log at the top level of the account. Projects come back newest first.

*GET /api/v1/projects → 200*

```json
{
  "projects": [
    { "id": "cm1x9k2...", "name": "My E30 Build" },
    { "id": "cm1x7q8...", "name": "Customer Car" }
  ]
}
```

## Step 8 · Upload logs

Multipart form data with these fields:

| Field | Value |
|---|---|
| `files` | One part per file, repeated. File name must end in `.csv`, content type `text/csv`. The maximum number of files per request depends on the user's plan (table below); over the limit the whole request is rejected with a 403 and nothing is stored. |
| `projectId` | Optional. A project id from Step 7. Must belong to the user, otherwise 400 `invalid_project`. |
| `notes` | Optional. A JSON array string with one entry per file in the same order, for example `["3rd gear pull", null, "4th gear pull"]`. |
| `externalIds` | Optional. A JSON array string with one entry per file in the same order, holding your own id for that log (a session id, up to 128 characters), or `null`. Ids are unique per Datazap account and per partner app, so two users can reuse the same id and your ids never collide with another app's. Sending a file again with an id already uploaded returns the existing log untouched, even if the project or note differ, so retries are safe. Make the id stable and unique across every installation of your app: a UUID (`crypto.randomUUID()`), or a session id namespaced by machine, never a bare per-machine counter, or a replacement laptop's session 1234 would be treated as the old one's. |

*POST /api/v1/logs/upload → 200*

```json
{
  "success": true,
  "uploadedCount": 2,
  "logs": [
    { "id": "cm2a1b3...", "filename": "2026-09-17_pull_3rd.csv", "duplicate": false },
    { "id": "cm2a1b4...", "filename": "2026-09-17_pull_4th.csv", "duplicate": false }
  ]
}
```

`uploadedCount` counts new logs only. A file whose `externalId` was seen before comes back with `duplicate: true` and the id of the log that already exists.

Limits depend on the user's Datazap plan, and the server enforces them before anything is stored. Surface the server's `error` message to the user; it already names the plan and the limit.

| Plan | Max files per upload request | Max file size | Max logs in account |
|---|---|---|---|
| Free | 3 | 3 MB | 100 |
| Pro | 10 | 5 MB | 1,000 |
| Tuner | 20 | 10 MB | Unlimited |

Values at the time of writing. 20 files per request is the API-wide ceiling. Rely on the 403 / 413 responses, or on `/me`, rather than hard-coding the rest.

## Step 9 · Plan and usage (optional)

Everything above works without this call: the upload endpoint rejects anything over the user's plan with a readable message and a code. Use it when you want to show the connected account, size batches to the plan, check file sizes before uploading, or warn before the log cap instead of after. Any valid token can call it, no extra scope. Cache the result; refresh it after a plan-related 403 or once a day, not on every upload.

*GET /api/v1/me → 200*

```json
{
  "username": "jpsimon",
  "plan": "pro",
  "planName": "Pro",
  "scopes": ["logs:write", "projects:read"],
  "limits": { "maxLogs": 1000, "maxFileSizeMb": 5, "maxFilesPerUpload": 10 },
  "usage": { "logs": 87 }
}
```

`maxLogs` is `null` on plans with no cap. `getAccount()` in the client above returns this object as-is.

## Putting it together

*send-to-datazap.js*

```javascript
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
```

## Integration patterns

### Send to Datazap

The basic version: a *Send to Datazap* action on a saved log, or on a multi-select of saved logs. Recommended behavior:

- Send a selection as one request rather than one request per file, up to the plan's `maxFilesPerUpload`. If you would rather not call `/me`, send 3 at a time; every plan allows at least that many.
- Offer the project picker from Step 7 and remember the last choice. Uploading without a project is fine too.
- Offer an optional note field before sending. Notes are the user's to write; whatever they enter is stored per file and shown with the log in Datazap, and leaving it empty is fine.
- Set `externalId` to your own id for the log. A second click on the same log then returns the existing one instead of a copy.

### Auto-upload

Once connected, the user toggles *Auto-upload to Datazap* and every completed logging session is queued automatically and uploaded when connectivity allows. The upload itself is the same call as above; what changes is that it now runs unattended, so the queue must tolerate offline periods, process termination, retries and account limits.

- **Opt in, default off.** Show the toggle only once the account is connected.
- **Persist first, upload second.** When a session ends, durably enqueue the file path, session id, note and project before any network work: a JSON file or SQLite in `userData`, written before the upload starts. The source file must stay on disk until its entry succeeds; if your app cleans up or renames session files, copy pending logs into app-controlled storage.
- **Drain from three places:** session end, app launch, and a timer while the app is running. On Electron, run the drain in the main process, not a renderer, so it survives window closes; the OS will not run it once the app quits, so drain on next launch.
- **Retries are safe.** Pass the session id as `externalId`. A retry after a timeout gets the same log back with `duplicate: true`. Remove entries from the queue on any successful response, duplicate or not.
- **Branch on error codes, not messages.** `log_limit_reached` pauses the queue. `file_too_large` names the file; park that one and keep the rest. `invalid_project` means the default project was deleted; clear it and retry. Network errors and 5xx back off exponentially; 429 waits for `Retry-After`.
- **Pause, do not flip the toggle.** A full account, a lost authorization, a missing scope or a deactivated app pauses draining and says why. Keep the pause as a machine-readable state (the constants below), not as message text, and keep the files queued: these are conditions of the connection, not of any file. Only a problem with a specific request parks files.
- **Clear the pause deliberately.** Nothing clears itself. Set the pause back to `null` after a successful reconnect and on app launch; the next pass costs one request and simply re-pauses if the condition still holds, which is also how a freed-up or upgraded account resumes on its own.
- **Default project (nice to have).** A good pattern is a project picker in the auto-upload settings, filled from Step 7, so every auto-upload lands in the project the user chose once. If no project is set, the log goes to the top level of their account, the same as a manual upload without a project. Leave the note empty unless the user set one.

*auto-upload.js*

```javascript
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
```

## Error reference

API errors are `{ "error": "readable message", "code": "stable_code" }`; 413 also carries `"filename"`. OAuth endpoint errors are `{ "error": "code", "error_description": "message" }` with the standard OAuth codes (`invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `unsupported_grant_type`). Branch on codes, never on message text. Authorization codes expire after 10 minutes and are single use.

| Status | Code | Meaning | What to do |
|---|---|---|---|
| `400` | `invalid_request` | Malformed `notes` or `externalIds` | Fix the request; not retryable as-is. |
| `400` | `invalid_project` | The `projectId` does not exist or belongs to someone else | Clear the stored project and retry without it. |
| `400` | `no_files` | No `files` parts in the request | Fix the request. |
| `401` | `missing_token`, `invalid_token`, `token_expired`, `token_revoked` | The access token is absent, unknown, expired or revoked | The client refreshes once and retries once. If that still fails, tokens are cleared: reconnect. |
| `403` | `missing_scope` | The connection was authorized without this scope | Reconnect requesting the scope. |
| `403` | `app_inactive` | Your app was deactivated on our side | Contact us. |
| `403` | `max_files_per_upload` | More files than the user's plan allows in one request | Split into smaller requests. |
| `403` | `log_limit_reached` | The account is at its plan's log cap | Pause and tell the user once. Nothing to retry until they free space or upgrade. |
| `413` | `file_too_large` | The named `filename` is over the plan's size cap; nothing was stored | Park that file, resend the others. |
| `429` | `rate_limited` | More than 60 requests in a minute with this access token | Wait for `Retry-After` seconds, then retry. Batch files into one upload call. |
| `5xx` | `server_error` | Server problem | Retry with backoff. Tell us if it persists. |

## User experience notes

- Users can disconnect your app at any time under Settings on datazap.me. Your next API call gets a 401, the refresh gets `invalid_grant`, and the client above clears its tokens.
- One connection per user and app. Authorizing again (for example on a second machine) replaces the earlier connection and its tokens.
- The consent screen shows your app name, logo and description. A square PNG or SVG of at least 128 px looks best.

## Testing checklist

1. Connect: the consent screen shows your app name and logo, approving returns to your app with a code, and the exchange succeeds.
2. Deny on the consent screen: your app handles `error=access_denied` without crashing.
3. List projects, then upload a CSV into one of them and confirm it appears at datazap.me.
4. Upload with an invalid `projectId`: expect 400 `invalid_project` with a readable message.
5. Upload the same file twice with the same `externalId`: the second response has `uploadedCount: 0` and the same log id with `duplicate: true`.
6. Force a refresh (set `expiresAt` in the past): the next call succeeds and the stored refresh token changed.
7. Disconnect from Datazap settings, then call the API: the client clears tokens and prompts to reconnect.
8. Disconnect the network and upload: the app reports a connection problem rather than crashing, and an auto-upload queue keeps the entry for later.

## Browser-only apps

A browser-only web app is also a public OAuth client and uses the same Authorization Code + PKCE flow, but its architecture differs from this guide: it uses a registered HTTPS redirect instead of a loopback listener, gets files from `<input type="file">` rather than disk paths, is subject to CORS, and has a different token-storage threat model because any same-origin script can read browser storage. The API calls themselves are identical. If you are building a browser-only integration, contact us first so we can confirm the redirect and CORS setup.

## Confidential clients

If your integration runs on a server you control, for example a web tool or a shop system that syncs from its own backend, we can register it as a *confidential client* instead. It gets a `client_secret`, and the token and revoke calls send it alongside `client_id`; everything else in this guide stays the same. Email **support@datazap.me** if you need that. Apps that ship to users' machines should stay public.

## Going live

Send us:

- App name and a one-line description (shown on the consent screen)
- App logo, square, at least 128 × 128 px, PNG or SVG
- Every redirect URI you will use: loopback URIs without a port, or claimed HTTPS links

We register the app and send back your `client_id`. Questions or a stuck integration: **support@datazap.me**.
