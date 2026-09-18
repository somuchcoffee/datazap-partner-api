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
