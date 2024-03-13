export interface DatabaseUser {
	id: string;
	username: string;
	github_id: number;
}

export interface DatabasePubKey {
	key_id: string;
	modulus: string;
	exponent: string;
	valid_from: Date;
	valid_until: Date | null;
	status: "active" | "inactive" | "revoked";
	created_at: Date;
	updated_at: Date;
}
