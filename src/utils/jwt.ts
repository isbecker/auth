import { getActivePulicKey } from "@db/pubkey";
import { User } from "lucia";
import { TimeSpan } from "oslo";
import { createJWT } from "oslo/jwt";

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

export const generateJWT = async (env: any, user: User): Promise<string> => {
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
