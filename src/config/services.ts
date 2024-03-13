import { GitHub } from 'arctic';
import { Env } from '@typing/env';

export function initializeGitHub(env: Env) {
  return new GitHub(
    env.GITHUB_CLIENT_ID,
    env.GITHUB_CLIENT_SECRET,
    { redirectURI: 'https://auth.beckr.dev/auth/github/callback' }
  );
}
