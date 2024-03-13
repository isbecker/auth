import { Lucia } from "lucia";

export function getSessionId(request: Request, lucia: Lucia): string | null {
	const httpCookie = request.headers.get("Cookie");
	const authorizationHeader = request.headers.get("Authorization");
	let sessionId: string | null = null;

	if (httpCookie) {
		sessionId = lucia.readSessionCookie(httpCookie);
	} else if (authorizationHeader) {
		sessionId = lucia.readBearerToken(authorizationHeader);
	}

	return sessionId;
}
