-- Migration number: 0002 	 2024-03-07T14:54:23.297Z
CREATE TABLE IF NOT EXISTS rsa_public_keys (
    key_id VARCHAR(36) PRIMARY KEY,
    modulus TEXT NOT NULL,
    exponent TEXT NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP,
    status VARCHAR(8) NOT NULL CHECK (status IN ('active', 'inactive', 'revoked')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
