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
