import { DatabasePubKey } from "@typing/db";

export async function getActivePulicKey(db: D1Database): Promise<DatabasePubKey> {
	return await db.prepare("SELECT * FROM rsa_public_keys WHERE status = 'active'").first() as DatabasePubKey;
}

export async function getInactivePulicKey(db: D1Database): Promise<DatabasePubKey> {
	return await db.prepare("SELECT * FROM rsa_public_keys WHERE status = 'inactive'").first() as DatabasePubKey;
}
