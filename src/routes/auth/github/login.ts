import { initializeGitHub } from '@config/services';
import { Env } from '@typing/env';

import { generateState } from 'arctic';


export const loginHandler = async (req: Request, env: Env): Promise<Response> => {
	const github = initializeGitHub(env);

	const state = generateState();
	const url = await github.createAuthorizationURL(state);
	const res = new Response(null, {
		status: 302,
		headers: {
			Location: url.toString(),
			"Set-Cookie": `github_oauth_state=${state};path=.;SameSite=lax;HttpOnly;Max-Age=600`
		}
	});

	return res;
}
