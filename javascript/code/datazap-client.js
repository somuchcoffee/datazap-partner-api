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
  #refreshing = null;   // in-flight refresh promise, so concurrent callers share one refresh

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
    // Wait for any in-flight refresh so it cannot re-save tokens after we clear them
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

    // Rejected anyway (clock skew, revoked elsewhere): refresh once and retry once
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
