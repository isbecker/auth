import { generateId } from "lucia";

export async function generateRefreshToken(db: D1Database, userId: string): Promise<string> {
	const tokenId = generateId(15);
	const refreshToken = generateId(36);
	await db.prepare("INSERT INTO refresh_tokens (id, token, user_id, expires_at) VALUES (?, ?, ?, DATETIME('now', '+30 days'))")
		.bind(tokenId, refreshToken, userId)
		.run();
	return refreshToken;
}

export async function consumeRefreshToken(db: D1Database, token: string): Promise<void> {
	await db.prepare("DELETE FROM refresh_tokens WHERE token = ?").bind(token).run();
}

export async function validateRefreshToken(db: D1Database, token: string): Promise<string | null> {
	const refreshToken = await db.prepare("SELECT user_id FROM refresh_tokens WHERE token = ? AND expires_at > DATETIME('now')")
		.bind(token)
		.first() as { user_id: string } | undefined;

	if (refreshToken) {
		return refreshToken.user_id; // Token is valid and not expired
	} else {
		// Token is invalid or expired; consider cleaning up expired tokens here or separately
		await db.prepare("DELETE FROM refresh_tokens WHERE token = ?").bind(token).run();
		return null;
	}
}
