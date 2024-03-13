import { Env } from "@typing/env";
import { generateJWT } from "@utils/jwt";
import { consumeRefreshToken, generateRefreshToken, validateRefreshToken } from "@utils/refresh";
import { Lucia } from "lucia";

export const refreshHandler = async (request: Request, lucia: Lucia, env: Env) => {
	const authorizationHeader = request.headers.get("Authorization");
	if (!authorizationHeader) {
		return new Response(null, {
			status: 401
		});
	}
	const token = authorizationHeader.split(" ")[1]; // Bearer <token>
	const userId = await validateRefreshToken(env.DB, token);
	if (!userId) {
		return new Response(null, {
			status: 401
		});
	}
	await consumeRefreshToken(env.DB, token);
	const refreshToken = await generateRefreshToken(env.DB, userId);
	const session = await lucia.createSession(userId, {});
	const sessionCookie = lucia.createSessionCookie(session.id);
	sessionCookie.attributes.domain = ".beckr.dev";
	const jwt = await generateJWT(env, { id: userId });
	const res = new Response(null, {
		status: 200,
		headers: {
			"Set-Cookie": sessionCookie.serialize(),
		}
	});

	res.headers.append("Set-Cookie", `AccessToken=${jwt};path=/;SameSite=lax;HttpOnly;Max-Age=${30 * 60};Secure;Domain=.beckr.dev`);
	res.headers.append("Set-Cookie", `RefreshToken=${refreshToken};path=/;SameSite=lax;HttpOnly;Max-Age=${30 * 24 * 60 * 60};Secure;Domain=.beckr.dev`);

	return res;
}
