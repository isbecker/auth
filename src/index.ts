import { webcrypto } from "node:crypto";
globalThis.crypto = webcrypto as Crypto;

import { D1Adapter } from "@lucia-auth/adapter-sqlite";
import { GitHub, OAuth2RequestError, generateState } from 'arctic';
import { parse } from "cookie";
import { Lucia, generateId } from "lucia";
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
				const existingUser = (await env.DB.prepare("SELECT * FROM user WHERE github_id = ?").bind(githubUser.id).first()) as
					| DatabaseUser
					| undefined;
				if (existingUser) {
					const session = await lucia.createSession(existingUser.id, {});
					const sessionCookie = lucia.createSessionCookie(session.id);
					sessionCookie.attributes.domain = ".beckr.dev";
					res.headers.append("Set-Cookie", sessionCookie.serialize());
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
				}

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
		} else if (pathname === '/auth/github/logout') {
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
		} else if (pathname === '/auth/github/verify') {
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
			if (session) {
				if (session.fresh) {
					const sessionCookie = lucia.createSessionCookie(session.id);
					sessionCookie.attributes.domain = ".beckr.dev";
					return new Response(null, {
						status: 200,
						headers: {
							"Set-Cookie": sessionCookie.serialize(),
						},
					});
				}
				const key = pemToArrayBuffer(env.PRIVATE_KEY)
				const pubkey = await getActivePulicKey(env.DB);
				const payload = {
					messaage: "Hello, World!"
				}
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

				// Everthing is good, just return 200
				return new Response(JSON.stringify({ auth: jwt }), {
					status: 200
				});
			}
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
				},
			});

		}

		return new Response(null, {
			status: 404,
		});
	}
};
