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
