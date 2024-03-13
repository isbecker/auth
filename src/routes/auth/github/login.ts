import { Env } from '@typing/env';

import { GitHub, generateState } from 'arctic';
import { Lucia } from 'lucia';


export const loginHandler = async (req: Request, github: GitHub, lucia: Lucia): Promise<Response> => {
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
