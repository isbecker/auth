import { webcrypto } from "node:crypto";
globalThis.crypto = webcrypto as Crypto;

import { initializeLucia } from "@config/luciaConfig";
import { callbackHandler } from "@routes/auth/github/callback";
import { loginHandler } from "@routes/auth/github/login";
import { logoutHandler } from "@routes/auth/logout";
import { refreshHandler } from "@routes/auth/refresh";
import { verifyHandler } from "@routes/auth/verify";
import { wellKnownJwksHandler, wellKnownOpenIDHandler } from "@routes/well-known";
import { Env } from "@typing/env";
import { Router } from "itty-router";

const router = Router();

router.get('/auth/github/login', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await loginHandler(request, env);
});
router.get('/auth/github/callback', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await callbackHandler(request, env);
});
router.get('/auth/logout', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await logoutHandler(request, env);
});
router.get('/auth/refresh', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await refreshHandler(request, env);
});
router.get('/auth/verify', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return verifyHandler(request, env);
});
router.get('/.well-known/openid-configuration', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await wellKnownOpenIDHandler(request, env);
});
router.get('/.well-known/jwks.json', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return await wellKnownJwksHandler(request, env);
});
router.all('*', async (request: Request, env: Env, ctx: ExecutionContext) => {
	return new Response(null, {
		status: 404,
	});
});

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return router.handle(request, env, ctx);
	},
	async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
		const lucia = initializeLucia(env.DB);
		ctx.waitUntil(lucia.deleteExpiredSessions());
	},
};
