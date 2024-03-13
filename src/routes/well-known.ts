import { getActivePulicKey, getInactivePulicKey } from "@db/pubkey";
import { Env } from "@typing/env";

export const wellKnownJwksHandler = async (request: Request, env: Env): Promise<Response> => {
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
}

export const wellKnownOpenIDHandler = async (request: Request, env: Env): Promise<Response> => {
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
