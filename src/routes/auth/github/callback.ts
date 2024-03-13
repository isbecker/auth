import { DatabaseUser } from "@typing/db";
import { Env } from "@typing/env";
import { GitHubUser } from "@typing/types";
import { generateJWT } from "@utils/jwt";
import { generateRefreshToken } from "@utils/refresh";
import { GitHub, OAuth2RequestError } from "arctic";
import { parse } from "cookie";
import { Lucia, User, generateId } from "lucia";

export const callbackHandler = async (request: Request, github: GitHub, lucia: Lucia, env: Env) => {
	const searchParams = new URL(request.url).searchParams;
	const code = searchParams.get('code');
	const state = searchParams.get('state');
	const httpCookie = parse(request.headers.get("Cookie") || "");
	const storedState = httpCookie["github_oauth_state"] ?? null;
	let res = new Response(null, { status: 302, headers: { Location: 'https://reader.beckr.dev' } });

	if (!code || !state || !storedState || state !== storedState) {
		return new Response(null, {
			status: 400
		});
	}
	try {
		const tokens = await github.validateAuthorizationCode(code);
		const githubUserResponse = await fetch("https://api.github.com/user", {
			headers: {
				Authorization: `Bearer ${tokens.accessToken}`,
				"User-Agent": "Cloudflare-Worker"
			}
		});
		const githubUser: GitHubUser = await githubUserResponse.json();
		let user: User;
		const existingUser = (await env.DB.prepare("SELECT * FROM user WHERE github_id = ?").bind(githubUser.id).first()) as
			| DatabaseUser
			| undefined;
		if (existingUser) {
			const session = await lucia.createSession(existingUser.id, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			sessionCookie.attributes.domain = ".beckr.dev";
			res.headers.append("Set-Cookie", sessionCookie.serialize());

			user = {
				id: existingUser.id,
			};
		} else {
			const userId = generateId(15);
			await env.DB.prepare("INSERT INTO user (id, github_id, username) VALUES (?, ?, ?)").bind(
				userId,
				githubUser.id,
				githubUser.login
			).run();
			const session = await lucia.createSession(userId, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			sessionCookie.attributes.domain = ".beckr.dev";
			res.headers.append("Set-Cookie", sessionCookie.serialize());

			user = {
				id: userId,
			};
		}

		const jwt = await generateJWT(env, user);
		const refreshToken = await generateRefreshToken(env.DB, user.id);
		res.headers.append("Set-Cookie", `AccessToken=${jwt};path=/;SameSite=lax;HttpOnly;Max-Age=${30 * 60};Secure;Domain=.beckr.dev`);
		res.headers.append("Set-Cookie", `RefreshToken=${refreshToken};path=/;SameSite=lax;HttpOnly;Max-Age=${30 * 24 * 60 * 60};Secure;Domain=.beckr.dev`);

		return res;

	} catch (error) {
		if (error instanceof OAuth2RequestError && error.message === "bad_verification_code") {
			// invalid code
			return new Response(null, {
				status: 400
			});
		}

		return new Response(null, {
			status: 500
		});
	}
}
