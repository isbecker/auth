import { webcrypto } from "node:crypto";
globalThis.crypto = webcrypto as Crypto;

import { initializeLucia } from "@config/luciaConfig";
import { initializeGitHub } from "@config/services";
import { callbackHandler } from "@routes/auth/github/callback";
import { loginHandler } from "@routes/auth/github/login";
import { logoutHandler } from "@routes/auth/logout";
import { refreshHandler } from "@routes/auth/refresh";
import { verifyHandler } from "@routes/auth/verify";
import { wellKnownJwksHandler, wellKnownOpenIDHandler } from "@routes/well-known";
import { Env } from "@typing/env";
import { Router } from "itty-router";

const router = Router();


export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {

		const github = initializeGitHub(env);
		const lucia = initializeLucia(env.DB);

		router.get('/auth/github/login', async (request: Request, env: Env, ctx: ExecutionContext) => {
			return await loginHandler(request, github, lucia);
		});
		router.get('/auth/github/callback', async (request: Request, env: Env, ctx: ExecutionContext) => {
			return await callbackHandler(request, github, lucia, env);
		});
		router.get('/auth/logout', async (request: Request, env: Env, ctx: ExecutionContext) => {
			return await logoutHandler(request, lucia);
		});
		router.get('/auth/refresh', async (request: Request, env: Env, ctx: ExecutionContext) => {
			return await refreshHandler(request, lucia, env);
		});
		router.get('/auth/verify', async (request: Request, env: Env, ctx: ExecutionContext) => {
			return verifyHandler(request, lucia, env);
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
		return router.handle(request, env, ctx);
	},
	async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
		const lucia = initializeLucia(env.DB);
		ctx.waitUntil(lucia.deleteExpiredSessions());
	},
};
