import { webcrypto } from "node:crypto";
globalThis.crypto = webcrypto as Crypto;

import { D1Adapter } from "@lucia-auth/adapter-sqlite";
import { GitHub, OAuth2RequestError, generateState } from 'arctic';
import { parse } from "cookie";
import { Lucia, User, generateId } from "lucia";
import { TimeSpan } from "oslo";
import { createJWT } from "oslo/jwt";


export interface Env {  // If you set another name in wrangler.toml as the value for 'binding',
	// replace "DB" with the variable name you defined.
	DB: D1Database;
}

export function initializeLucia(D1: D1Database) {
	const adapter = new D1Adapter(D1, {
		user: "user",
		session: "session"
	});
	return new Lucia(adapter);
}

declare module "lucia" {
	interface Register {
		Auth: ReturnType<typeof initializeLucia>;
	}
}

interface DatabaseUser {
	id: string;
	username: string;
	github_id: number;
}
interface GitHubUser {
	id: string;
	login: string;
}

interface DatabasePubKey {
	key_id: string;
	modulus: string;
	exponent: string;
	valid_from: Date;
	valid_until: Date | null;
	status: "active" | "inactive" | "revoked";
	created_at: Date;
	updated_at: Date;
}


function getSessionId(request: Request, lucia: Lucia): string | null {
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

function pemToArrayBuffer(pem: string) {
	// Remove PEM header and footer
	const base64String = pem
		.replace('-----BEGIN PRIVATE KEY-----', '')
		.replace('-----END PRIVATE KEY-----', '')
		.replace(/\s+/g, ''); // Remove whitespace

	// Base64 decode the string to get the binary data
	const binaryString = atob(base64String);

	// Convert the binary string to an ArrayBuffer
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}

	return bytes.buffer;
}

async function getActivePulicKey(db: D1Database): Promise<DatabasePubKey> {
	return await db.prepare("SELECT * FROM rsa_public_keys WHERE status = 'active'").first() as DatabasePubKey;
}

async function getInactivePulicKey(db: D1Database): Promise<DatabasePubKey> {
	return await db.prepare("SELECT * FROM rsa_public_keys WHERE status = 'inactive'").first() as DatabasePubKey;
}

async function generateRefreshToken(db: D1Database, userId: string): Promise<string> {
	// First check to see if we already have a refresh token for this user
	const existingToken = await db.prepare("SELECT token FROM refresh_tokens WHERE user_id = ?").bind(userId).first() as { token: string, expires_at: Date } | undefined;
	if (existingToken) {
		if (existingToken.expires_at < new Date()) {
			await db.prepare("DELETE FROM refresh_tokens WHERE token = ?").bind(existingToken.token).run();
		} else {
			return existingToken.token;
		}
	}
	const refreshToken = generateId(36);
	await db.prepare("INSERT INTO refresh_tokens (token, user_id, issued_at, expires_at) VALUES (?, ?)")
		.bind(refreshToken, userId, new Date(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
		.run();
	return refreshToken;
}

async function consumeRefreshToken(db: D1Database, token: string): Promise<void> {
	await db.prepare("DELETE FROM refresh_tokens WHERE token = ?").bind(token).run();
}

async function validateRefreshToken(db: D1Database, token: string): Promise<string | null> {
	const refreshToken = await db.prepare("SELECT user_id FROM refresh_tokens WHERE token = ?").bind(token).first() as { user_id: string, expires_at: Date } | undefined;
	if (refreshToken) {
		if (refreshToken.expires_at < new Date()) {
			await db.prepare("DELETE FROM refresh_tokens WHERE token = ?").bind(token).run();
			return null;
		}
		return refreshToken.user_id;
	}
	return null;
}

const generateJWT = async (env: any, user: User): Promise<string> => {
	const key = pemToArrayBuffer(env.PRIVATE_KEY);
	const pubkey = await getActivePulicKey(env.DB);
	const payload = {
		entitlements: ["reader", "summary"],
	};
	const jwt = await createJWT("RS256", key, payload, {
		headers: {
			kid: pubkey.key_id
		},
		expiresIn: new TimeSpan(30, "m"),
		issuer: "https://auth.beckr.dev",
		subject: user.id,
		audiences: ["https://reader.beckr.dev"],
		includeIssuedTimestamp: true,
	});

	return jwt;
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {

		const github = new GitHub(
			env.GITHUB_CLIENT_ID,
			env.GITHUB_CLIENT_SECRET,
			{
				redirectURI: 'https://auth.beckr.dev/auth/github/callback',
			}
		);
		const { searchParams, pathname } = new URL(request.url);
		const lucia = initializeLucia(env.DB);
		if (pathname === '/auth/github/login') {
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
		else if (pathname === '/auth/github/callback') {
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
		} else if (pathname === '/auth/logout') {
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
		} else if (pathname === '/auth/verify') {
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
		} else if (pathname === '/auth/refresh') {
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
		} else if (pathname === '/.well-known/jwks.json') {
			const active = await getActivePulicKey(env.DB);

			const jwk = {
				kty: 'RSA',
				use: 'sig',
				alg: 'RS256',
				n: active.modulus,
				e: active.exponent,
				kid: active.key_id,
			};

			const inactive = await getInactivePulicKey(env.DB);
			const inactiveKey = {
				kty: 'RSA',
				use: 'sig',
				alg: 'RS256',
				n: inactive.modulus,
				e: inactive.exponent,
				kid: inactive.key_id,
			};

			return new Response(JSON.stringify({ keys: [jwk, inactiveKey] }), {
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*', // Allow requests from any origin
					'Access-Control-Allow-Methods': 'GET', // Allow GET requests
					'Access-Control-Allow-Headers': 'Content-Type', // Allow Content-Type header
				},
			});

		} else if (pathname === '/.well-known/openid-configuration') {

			return new Response(JSON.stringify({
				issuer: "https://auth.beckr.dev",
				jwks_uri: "https://auth.beckr.dev/.well-known/jwks.json",
			}), {
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*', // Allow requests from any origin
					'Access-Control-Allow-Methods': 'GET', // Allow GET requests
					'Access-Control-Allow-Headers': 'Content-Type', // Allow Content-Type header
				}
			});
		}

		return new Response(null, {
			status: 404,
		});
	}
};
