"use strict";

//My Subtle Crypto imports
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LENGTH = 16;           // 128 bits for salt
const IV_LENGTH = 12;             // 96 bits for AES-GCM IV
const AES_KEY_LENGTH = 32;        // 256 bits for AES key
const GCM_TAG_LENGTH = 16;        // 128 bits for AES-GCM authentication tag

/*
*GROUP MEMBERS
*    136896 - Mulindwa Able Mwesigwa
*    121183 - Phillip Akoragye
*    146408 Kenslie Oguta
*/

/********* Implementation ********/
class Keychain {
    /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
    constructor(salt, hmacKey, aesKey, kvs = {}) {
        this.data = {
            /* Store member variables that you intend to be public here
            (i.e. information that will not compromise security if an adversary sees) */
            salt: salt,           // Salt for PBKDF2 - needed for key recreation, safe to store
            kvs: kvs              // Key-value store: hashed_domain -> encrypted_password
        };
        this.secrets = {
            /* Store member variables that you intend to be private here
            (information that an adversary should NOT see). */
            hmacKey: hmacKey,     // HMAC key for domain name hashing
            aesKey: aesKey        // AES key for password encryption/decryption
        };
    }

    /**
     * Private helper method to hash domain names using HMAC-SHA256
     */
    async _hashDomain(domain) {
        const normalizedDomain = domain.toLowerCase().trim();
        const domainBuffer = Keychain.stringToBuffer(normalizedDomain);
        const hmacResult = await subtle.sign("HMAC", this.secrets.hmacKey, domainBuffer);
        return Keychain.bufferToBase64(hmacResult);
    }

    /**
     * Private helper method to validate that the keychain is properly initialized
     */
    _validateInitialization() {
        if (!this.secrets.hmacKey || !this.secrets.aesKey || !this.data.salt) {
            throw new Error("Keychain not properly initialized.");
        }
    }

    /**
     * Encrypts a password using AES-GCM with length hiding and domain binding
     */
    async _encryptPassword(password, domain) {
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new Error(`Password exceeds maximum length of ${MAX_PASSWORD_LENGTH} characters`);
        }

        // Pad password to hide actual length
        const paddedPassword = password.padEnd(MAX_PASSWORD_LENGTH, '\0');
        const passwordBuffer = Keychain.stringToBuffer(paddedPassword);

        // Use normalized domain as Additional Authenticated Data (AAD) for swap attack protection
        const normalizedDomain = domain.toLowerCase().trim();
        const domainBuffer = Keychain.stringToBuffer(normalizedDomain);

        // Generate a unique random IV for this encryption
        const iv = Keychain.getRandomBytes(IV_LENGTH);

        // Encrypt using AES-GCM with domain binding (AAD)
        const encrypted = await subtle.encrypt(
            { name: "AES-GCM", iv: iv, additionalData: domainBuffer },
            this.secrets.aesKey,
            passwordBuffer
        );

        // Combine IV + ciphertext for storage
        const combined = new Uint8Array(IV_LENGTH + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), IV_LENGTH);

        return Keychain.bufferToBase64(combined);
    }

    /**
     * Decrypts a password using AES-GCM with domain verification
     */
    async _decryptPassword(encryptedData, domain) {
        const combined = Keychain.base64ToBuffer(encryptedData);

        if (combined.length < IV_LENGTH + GCM_TAG_LENGTH) {
            throw new Error("Encrypted data is too short to be valid.");
        }

        const iv = combined.slice(0, IV_LENGTH);
        const ciphertext = combined.slice(IV_LENGTH);

        // Prepare domain for AAD verification
        const normalizedDomain = domain.toLowerCase().trim();
        const domainBuffer = Keychain.stringToBuffer(normalizedDomain);

        // Decrypt, this will fail if the AAD (domain) or key is incorrect
        const decrypted = await subtle.decrypt(
            { name: "AES-GCM", iv: iv, additionalData: domainBuffer },
            this.secrets.aesKey,
            ciphertext
        );

        // Convert back to string and remove null padding
        const paddedPassword = Keychain.bufferToString(decrypted);
        return paddedPassword.replace(/\0+$/, '');
    }

    /**
     * Derives cryptographic keys from a master password using PBKDF2 and HMAC-PRF
     * @private
     */
    static async _deriveKeys(password, salt) {
        const passwordKey = await subtle.importKey(
            "raw", Keychain.stringToBuffer(password), "PBKDF2", false, ["deriveKey"]
        );

        // Derive a master key using PBKDF2
        const masterKey = await subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
            passwordKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true, ["sign"]
        );

        // Use HMAC as a PRF to derive domain-hashing and password-encrypting keys
        const hmacKeyMaterial = await subtle.sign("HMAC", masterKey, Keychain.stringToBuffer("HMAC_KEY"));
        const aesKeyMaterial = await subtle.sign("HMAC", masterKey, Keychain.stringToBuffer("AES_KEY"));

        const hmacKey = await subtle.importKey(
            "raw", hmacKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );

        const aesKey = await subtle.importKey(
            "raw", new Uint8Array(aesKeyMaterial).slice(0, AES_KEY_LENGTH), "AES-GCM", false, ["encrypt", "decrypt"]
        );

        return { hmacKey, aesKey };
    }

    /**
     * Generates a cryptographically secure random salt
     */
    static _generateSalt() {
        const salt = new Uint8Array(SALT_LENGTH);
        return webcrypto.getRandomValues(salt);
    }

    /**
     * Creates an empty keychain with the given password.
     */
    static async init(password) {
        if (!password || typeof password !== 'string') {
            throw new Error("Password must be a non-empty string");
        }
        const salt = Keychain._generateSalt();
        const { hmacKey, aesKey } = await Keychain._deriveKeys(password, salt);
        return new Keychain(salt, hmacKey, aesKey, {});
    }

    /**
     * Loads the keychain state from the provided representation (repr).
     */
    static async load(password, repr, trustedDataCheck) {
        if (!password || typeof password !== 'string') {
            throw new Error("Password must be a non-empty string");
        }
        if (!repr || typeof repr !== 'string') {
            throw new Error("Representation must be a non-empty string");
        }

        // Verify integrity if checksum is provided
        if (trustedDataCheck) {
            const computedHashBuffer = await subtle.digest("SHA-256", Keychain.stringToBuffer(repr));
            const computedChecksum = Keychain.bufferToBase64(computedHashBuffer);
            if (computedChecksum !== trustedDataCheck) {
                throw new Error("Integrity check failed - data may have been tampered with");
            }
        }

        const parsedData = JSON.parse(repr);
        const salt = Keychain.base64ToBuffer(parsedData.salt);

        // Re-derive keys to decrypt. If password is wrong, this will lead to decryption
        // errors later, which is the expected failure mode.
        const { hmacKey, aesKey } = await Keychain._deriveKeys(password, salt);

        return new Keychain(salt, hmacKey, aesKey, parsedData.kvs);
    }

    /**
     * Returns a JSON serialization of the keychain and a SHA-256 checksum.
     */
    async dump() {
        this._validateInitialization();

        const dumpData = {
            salt: Keychain.bufferToBase64(this.data.salt),
            kvs: this.data.kvs
        };

        const serializedData = JSON.stringify(dumpData);
        const hashBuffer = await subtle.digest("SHA-256", Keychain.stringToBuffer(serializedData));
        const checksumString = Keychain.bufferToBase64(hashBuffer);

        return [serializedData, checksumString];
    }

    /**
     * Fetches the password for the given domain. Returns null if not found.
     */
    async get(name) {
        this._validateInitialization();
        const hashedDomain = await this._hashDomain(name);
        const encryptedPassword = this.data.kvs[hashedDomain];

        if (encryptedPassword === undefined) {
            return null;
        }

        try {
            return await this._decryptPassword(encryptedPassword, name);
        } catch (e) {
            // This will catch errors from incorrect master password (AAD/tag mismatch)
            // console.error(`Decryption failed for domain "${name}". This may be due to a wrong master password or data corruption.`);
            return null;
        }
    }

    /**
     * Inserts or updates the password for the given domain.
     */
    async set(name, value) {
        this._validateInitialization();
        const hashedDomain = await this._hashDomain(name);
        const encryptedPassword = await this._encryptPassword(value, name);
        this.data.kvs[hashedDomain] = encryptedPassword;
    }

    /**
     * Removes the record for the given domain. Returns true if removed, false otherwise.
     */
    async remove(name) {
        this._validateInitialization();
        const hashedDomain = await this._hashDomain(name);

        if (hashedDomain in this.data.kvs) {
            delete this.data.kvs[hashedDomain];
            return true;
        }
        return false;
    }
}

module.exports = { Keychain };