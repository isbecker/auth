import { initializeLucia } from "@config/luciaConfig";
import { Env } from "@typing/env";
import { getSessionId } from "@utils/session";
import { Lucia } from "lucia";

export const verifyHandler = async (request: Request, env: Env) => {
	const lucia: Lucia = initializeLucia(env.DB);

	const sessionId = getSessionId(request, lucia);
	if (!sessionId) {
		return new Response(null, {
			status: 401
		});
	}

	const { session, user } = await lucia.validateSession(sessionId);
	if (!session) {
		const sessionCookie = lucia.createBlankSessionCookie();
		sessionCookie.attributes.domain = ".beckr.dev";
		return new Response(null, {
			status: 401,
			headers: {
				"Set-Cookie": sessionCookie.serialize(),
			},
		});
	}
	let res = new Response(null, {
		status: 200
	});
	if (session) {
		if (session.fresh) {
			const sessionCookie = lucia.createSessionCookie(session.id);
			sessionCookie.attributes.domain = ".beckr.dev";
			res.headers.append("Set-Cookie", sessionCookie.serialize());
		}

		return res;
	}
}
