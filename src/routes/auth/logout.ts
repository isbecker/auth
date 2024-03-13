import { initializeLucia } from "@config/luciaConfig";
import { Env } from "@typing/env";
import { getSessionId } from "@utils/session";
import { Lucia } from "lucia";

export const logoutHandler = async (request: Request, env: Env): Promise<Response> => {
	const lucia: Lucia = initializeLucia(env.DB);

	const sessionId = getSessionId(request, lucia);
	if (!sessionId) {
		return new Response(null, {
			status: 401
		});
	}
	await lucia.invalidateSession(sessionId);
	const sessionCookie = lucia.createBlankSessionCookie();
	sessionCookie.attributes.domain = ".beckr.dev";
	return new Response(null, {
		status: 302,
		headers: {
			Location: 'https://reader.beckr.dev',
			"Set-Cookie": sessionCookie.serialize()
		}
	});
}

