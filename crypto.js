/**
 * EncDec Pro Crypto Engine v5.1.0 (JavaScript / Web Crypto API)
 * =========================================================================
 * 100% Unified Military-Grade Cryptography Architecture:
 * - All 10 Key Profiles (Key 1 to Key 10) use AES-256-GCM AEAD (256-bit Key, 96-bit Nonce, 128-bit Auth Tag)
 * - Memory-Hard KDF: Scrypt (RFC 7914, N=16384..524288, 16MB..512MB RAM) across all 10 profiles
 * - Dual-Factor Keyfile Authentication (.key, .bin, arbitrary file)
 * - Next-Gen Self-Describing ENC5 Envelopes & ENC5F\x02 Binary Containers
 * - Full Legacy Compatibility: Automatically recognizes and decrypts legacy ENC4 Fernet envelopes and containers
 * - High-Entropy Diceware Passphrase & Cryptographic Password Generator
 */

(function(root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.EncDecCrypto = factory();
    }
}(typeof self !== 'undefined' ? self : this, function() {
    'use strict';

    const MAGIC_HEADER_V5 = "ENC5:";
    const MAGIC_HEADER_V4 = "ENC4:";
    const FILE_MAGIC_V5 = new Uint8Array([0x45, 0x4E, 0x43, 0x35, 0x46, 0x02]); // b"ENC5F\x02"
    const FILE_MAGIC_V4 = new Uint8Array([0x45, 0x4E, 0x43, 0x34, 0x46, 0x01]); // b"ENC4F\x01"

    // All 10 Key Profiles (Key 1 to Key 10) Upgraded to AES-256-GCM & Graded Memory-Hard Scrypt
    const KEY_CONFIGS = {
        "Key 1": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 16384,   // 16 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 1",
            label: "Key 1 (Fast - 16MB Memory-Hard + AES-256-GCM)",
            securityRating: "Fast Memory-Hard"
        },
        "Key 2": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 32768,   // 32 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 2",
            label: "Key 2 (Standard - 32MB Memory-Hard + AES-256-GCM)",
            securityRating: "Standard Memory-Hard"
        },
        "Key 3": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 32768,   // 48 MB
            scryptR: 12,
            scryptP: 1,
            alias: "Key 3",
            label: "Key 3 (Enhanced - 48MB Memory-Hard + AES-256-GCM)",
            securityRating: "Enhanced Security"
        },
        "Key 4": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 65536,   // 64 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 4",
            label: "Key 4 (High - 64MB Memory-Hard + AES-256-GCM)",
            securityRating: "High Security (AEAD)"
        },
        "Key 5": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 65536,   // 96 MB
            scryptR: 12,
            scryptP: 1,
            alias: "Key 5",
            label: "Key 5 (High+ - 96MB Memory-Hard + AES-256-GCM)",
            securityRating: "High+ Vault Grade"
        },
        "Key 6": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 131072,  // 128 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 6",
            label: "Key 6 (Strong - 128MB Memory-Hard + AES-256-GCM)",
            securityRating: "Strong Vault Grade"
        },
        "Key 7": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 131072,  // 160 MB
            scryptR: 10,
            scryptP: 1,
            alias: "Key 7",
            label: "Key 7 (Very Strong - 160MB Memory-Hard + AES-256-GCM)",
            securityRating: "Very Strong Vault"
        },
        "Key 8": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 131072,  // 192 MB
            scryptR: 12,
            scryptP: 1,
            alias: "Key 8",
            label: "Key 8 (Ultra - 192MB Memory-Hard + AES-256-GCM)",
            securityRating: "Supercomputer-Proof"
        },
        "Key 9": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 262144,  // 256 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 9",
            label: "Key 9 (Extreme - 256MB Memory-Hard + AES-256-GCM)",
            securityRating: "Military Vault Grade"
        },
        "Key 10": {
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            saltLength: 32,
            scryptN: 524288,  // 512 MB
            scryptR: 8,
            scryptP: 1,
            alias: "Key 10",
            label: "Key 10 (Paranoid - 512MB Memory-Hard + AES-256-GCM)",
            securityRating: "Quantum / ASIC Proof"
        }
    };

    // Legacy PBKDF2 iterations mapping for decrypting old ciphertexts
    const LEGACY_PBKDF2_MAP = {
        "Key 1": 100000,
        "Key 2": 200000,
        "Key 3": 300000,
        "Key 4": 400000,
        "Key 5": 500000,
        "Key 6": 800000,
        "Key 7": 1000000,
        "Key 8": 1200000,
        "Key 9": 1500000,
        "Key 10": 2000000
    };

    const ALIAS_MAP = {};
    for (const [k, v] of Object.entries(KEY_CONFIGS)) {
        ALIAS_MAP[k] = v;
        ALIAS_MAP[v.alias] = v;
        ALIAS_MAP[v.label] = v;
    }

    function getKeyConfig(name) {
        if (name && ALIAS_MAP[name]) return ALIAS_MAP[name];
        return KEY_CONFIGS["Key 4"];
    }

    const getCrypto = () => {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto;
        }
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto;
        }
        try {
            return require('crypto').webcrypto;
        } catch (e) {
            throw new Error('Web Crypto API is not available.');
        }
    };

    // Base64 URL-Safe Conversions
    function toBase64Url(uint8Array, pad = true) {
        let binary = '';
        const len = uint8Array.byteLength;
        const chunkSize = 0x8000;
        for (let i = 0; i < len; i += chunkSize) {
            const chunk = uint8Array.subarray(i, Math.min(i + chunkSize, len));
            binary += String.fromCharCode.apply(null, chunk);
        }
        let b64 = (typeof btoa !== 'undefined' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64'))
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
        if (!pad) {
            b64 = b64.replace(/=+$/, '');
        }
        return b64;
    }

    function fromBase64Url(base64UrlStr) {
        if (!base64UrlStr) return new Uint8Array(0);
        let base64 = base64UrlStr.trim().replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        let binary;
        if (typeof atob !== 'undefined') {
            binary = atob(base64);
        } else {
            binary = Buffer.from(base64, 'base64').toString('binary');
        }
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    async function sha256(dataBytes) {
        const cryptoInstance = getCrypto();
        const digestBuffer = await cryptoInstance.subtle.digest('SHA-256', dataBytes);
        return new Uint8Array(digestBuffer);
    }

    async function prepareKeyMaterial(password, keyfileBytes = null) {
        const enc = new TextEncoder();
        const passBytes = enc.encode(password);
        if (!keyfileBytes || keyfileBytes.length === 0) {
            return passBytes;
        }
        const kfHash = await sha256(keyfileBytes);
        const marker = enc.encode('::KEYFILE::');
        const combined = new Uint8Array(passBytes.length + marker.length + kfHash.length);
        combined.set(passBytes, 0);
        combined.set(marker, passBytes.length);
        combined.set(kfHash, passBytes.length + marker.length);
        return combined;
    }

    // =========================================================================
    // Memory-Hard Scrypt Engine (RFC 7914)
    // =========================================================================

    function salsa20_8(B) {
        const B32 = new Int32Array(B.buffer, B.byteOffset, 16);
        const x = new Int32Array(16);
        for (let i = 0; i < 16; i++) x[i] = B32[i];

        function R(a, b) { return (a << b) | (a >>> (32 - b)); }

        for (let i = 8; i > 0; i -= 2) {
            x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
            x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
            x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
            x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
            x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
            x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
            x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
            x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
            x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
            x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
            x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
            x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
            x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
            x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
            x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
            x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
        }
        for (let i = 0; i < 16; i++) B32[i] += x[i];
    }

    function blockmix_salsa8(B, Y, r) {
        const X = new Uint8Array(64);
        X.set(B.subarray((2 * r - 1) * 64, 2 * r * 64));
        for (let i = 0; i < 2 * r; i++) {
            for (let j = 0; j < 64; j++) X[j] ^= B[i * 64 + j];
            salsa20_8(X);
            const dest = (i % 2 === 0) ? (i / 2) * 64 : (r + (i - 1) / 2) * 64;
            Y.set(X, dest);
        }
        B.set(Y);
    }

    function smix(B, r, N, V, XY) {
        const len = 128 * r;
        const X = XY.subarray(0, len);
        const Y = XY.subarray(len, 2 * len);

        X.set(B);
        for (let i = 0; i < N; i++) {
            V.set(X, i * len);
            blockmix_salsa8(X, Y, r);
        }
        for (let i = 0; i < N; i++) {
            const j = (new Int32Array(X.buffer, X.byteOffset + (2 * r - 1) * 64, 1)[0] & (N - 1)) * len;
            for (let k = 0; k < len; k++) X[k] ^= V[j + k];
            blockmix_salsa8(X, Y, r);
        }
        B.set(X);
    }

    async function pbkdf2Sha256(passwordBytes, saltBytes, iterations, dkLen) {
        const cryptoInstance = getCrypto();
        const keyMaterial = await cryptoInstance.subtle.importKey(
            'raw',
            passwordBytes,
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );
        const bits = await cryptoInstance.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            dkLen * 8
        );
        return new Uint8Array(bits);
    }

    async function deriveScrypt(passwordBytes, saltBytes, N = 65536, r = 8, p = 1, dkLen = 32) {
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            try {
                const nodeCrypto = require('crypto');
                if (nodeCrypto && nodeCrypto.scryptSync) {
                    const res = nodeCrypto.scryptSync(passwordBytes, saltBytes, dkLen, { N, r, p, maxmem: 1024 * 1024 * 1024 });
                    return new Uint8Array(res);
                }
            } catch (e) {}
        }

        const B = await pbkdf2Sha256(passwordBytes, saltBytes, 1, p * 128 * r);
        const V = new Uint8Array(N * 128 * r);
        const XY = new Uint8Array(256 * r);
        for (let i = 0; i < p; i++) {
            smix(B.subarray(i * 128 * r, (i + 1) * 128 * r), r, N, V, XY);
        }
        return await pbkdf2Sha256(passwordBytes, B, 1, dkLen);
    }

    async function deriveMasterKey(password, salt, config, keyfileBytes = null, length = 32) {
        const material = await prepareKeyMaterial(password, keyfileBytes);
        const N = config.scryptN || 65536;
        const r = config.scryptR || 8;
        const p = config.scryptP || 1;
        return await deriveScrypt(material, salt, N, r, p, length);
    }

    // =========================================================================
    // AES-256-GCM AEAD Engine
    // =========================================================================

    async function encryptAesGcm(plainBytes, keyBytes, nonceBytes = null) {
        const cryptoInstance = getCrypto();
        const nonce = nonceBytes || cryptoInstance.getRandomValues(new Uint8Array(12));
        const key = await cryptoInstance.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        const cipherBuffer = await cryptoInstance.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            key,
            plainBytes
        );
        return {
            nonce: nonce,
            ciphertext: new Uint8Array(cipherBuffer)
        };
    }

    async function decryptAesGcm(cipherBytes, keyBytes, nonceBytes) {
        const cryptoInstance = getCrypto();
        const key = await cryptoInstance.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        const plainBuffer = await cryptoInstance.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
            key,
            cipherBytes
        );
        return new Uint8Array(plainBuffer);
    }

    // =========================================================================
    // Legacy Fernet Token Engine (AES-128-CBC + HMAC-SHA256)
    // =========================================================================

    async function decryptFernetToken(fernetTokenB64OrBytes, derivedKey) {
        const cryptoInstance = getCrypto();
        let fernetTokenB64 = fernetTokenB64OrBytes;
        if (fernetTokenB64OrBytes instanceof Uint8Array) {
            fernetTokenB64 = new TextDecoder().decode(fernetTokenB64OrBytes);
        }

        const fernetTokenRaw = fromBase64Url(fernetTokenB64);
        if (fernetTokenRaw.length < 57) {
            throw new Error('Invalid Fernet token length.');
        }

        if (fernetTokenRaw[0] !== 0x80) {
            throw new Error('Unsupported Fernet version byte (expected 0x80).');
        }

        const signingKeyBytes = derivedKey.slice(0, 16);
        const encryptionKeyBytes = derivedKey.slice(16, 32);

        const payloadToVerify = fernetTokenRaw.slice(0, -32);
        const signature = fernetTokenRaw.slice(-32);

        const hmacKey = await cryptoInstance.subtle.importKey(
            'raw',
            signingKeyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );

        const isValidSig = await cryptoInstance.subtle.verify('HMAC', hmacKey, signature, payloadToVerify);
        if (!isValidSig) {
            throw new Error('HMAC signature verification failed.');
        }

        const iv = payloadToVerify.slice(9, 25);
        const cipherBytes = payloadToVerify.slice(25);

        const aesKey = await cryptoInstance.subtle.importKey(
            'raw',
            encryptionKeyBytes,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );

        const decryptedBuffer = await cryptoInstance.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            aesKey,
            cipherBytes
        );

        return new Uint8Array(decryptedBuffer);
    }

    // =========================================================================
    // Text Encryption & Decryption
    // =========================================================================

    async function encryptText(plainText, password, keyType = "Key 4", useEnvelope = true, keyfileBytes = null) {
        if (!plainText || !password) return "";
        const config = getKeyConfig(keyType);
        const cryptoInstance = getCrypto();
        const salt = cryptoInstance.getRandomValues(new Uint8Array(config.saltLength));
        const derivedKey = await deriveMasterKey(password, salt, config, keyfileBytes, 32);

        const { nonce, ciphertext } = await encryptAesGcm(new TextEncoder().encode(plainText), derivedKey);
        if (useEnvelope) {
            const saltB64 = toBase64Url(salt, true);
            const nonceB64 = toBase64Url(nonce, true);
            const cipherB64 = toBase64Url(ciphertext, true);
            const alias = config.alias;
            return `${MAGIC_HEADER_V5}${alias}:scrypt:${saltB64}:${nonceB64}:${cipherB64}`;
        } else {
            const combined = new Uint8Array(salt.length + nonce.length + ciphertext.length);
            combined.set(salt, 0);
            combined.set(nonce, salt.length);
            combined.set(ciphertext, salt.length + nonce.length);
            return toBase64Url(combined, true);
        }
    }

    async function decryptText(encryptedText, password, keyType = "Key 4", keyfileBytes = null) {
        if (!encryptedText || !password) {
            return { success: false, decryptedText: "", keyAlias: "", error: "Missing text or password" };
        }

        const s = encryptedText.trim();

        // 1. ENC5: Modern AES-256-GCM Envelope (ENC5:alias:kdf:salt_b64:nonce_b64:cipher_b64)
        if (s.startsWith(MAGIC_HEADER_V5)) {
            try {
                const parts = s.split(":");
                if (parts.length >= 6) {
                    const alias = parts[1];
                    const kdfTag = parts[2];
                    const salt = fromBase64Url(parts[3]);
                    const nonce = fromBase64Url(parts[4]);
                    const ciphertext = fromBase64Url(parts.slice(5).join(":"));
                    const config = getKeyConfig(alias);
                    const derivedKey = await deriveMasterKey(password, salt, config, keyfileBytes, 32);
                    const decryptedBytes = await decryptAesGcm(ciphertext, derivedKey, nonce);
                    return {
                        success: true,
                        decryptedText: new TextDecoder().decode(decryptedBytes),
                        keyAlias: alias,
                        cipher: "AES-256-GCM",
                        kdf: kdfTag
                    };
                }
            } catch (e) {}
        }

        // 2. ENC4: Legacy Fernet Envelope (ENC4:alias:salt_b64:cipher_b64)
        if (s.startsWith(MAGIC_HEADER_V4)) {
            try {
                const parts = s.split(":");
                if (parts.length >= 4) {
                    const alias = parts[1];
                    const saltB64 = parts[2];
                    const cipherB64 = parts.slice(3).join(":");
                    const salt = fromBase64Url(saltB64);
                    const iters = LEGACY_PBKDF2_MAP[alias] || 200000;
                    const legacyKey = await pbkdf2Sha256(new TextEncoder().encode(password), salt, iters, 32);
                    const decryptedBytes = await decryptFernetToken(cipherB64, legacyKey);
                    return {
                        success: true,
                        decryptedText: new TextDecoder().decode(decryptedBytes),
                        keyAlias: `${alias} (Legacy Fernet)`,
                        cipher: "Fernet-128"
                    };
                }
            } catch (e) {}
        }

        // 3. Fallback: probe all 10 V5 configurations
        for (const [k, config] of Object.entries(KEY_CONFIGS)) {
            try {
                const rawBytes = fromBase64Url(s);
                const saltLength = config.saltLength;
                if (rawBytes.length > saltLength + 12 + 16) {
                    const salt = rawBytes.slice(0, saltLength);
                    const nonce = rawBytes.slice(saltLength, saltLength + 12);
                    const cipherBytes = rawBytes.slice(saltLength + 12);
                    const derivedKey = await deriveMasterKey(password, salt, config, keyfileBytes, 32);
                    const decryptedBytes = await decryptAesGcm(cipherBytes, derivedKey, nonce);
                    return {
                        success: true,
                        decryptedText: new TextDecoder().decode(decryptedBytes),
                        keyAlias: config.alias,
                        cipher: "AES-256-GCM"
                    };
                }
            } catch (e) {
                continue;
            }
        }

        // 4. Fallback: probe all Legacy PBKDF2 configurations
        for (const [alias, iters] of Object.entries(LEGACY_PBKDF2_MAP)) {
            try {
                const rawBytes = fromBase64Url(s);
                const saltLen = alias === "Key 1" ? 16 : 32;
                if (rawBytes.length > saltLen + 57) {
                    const salt = rawBytes.slice(0, saltLen);
                    const cipherBytes = rawBytes.slice(saltLen);
                    const legacyKey = await pbkdf2Sha256(new TextEncoder().encode(password), salt, iters, 32);
                    const decryptedBytes = await decryptFernetToken(cipherBytes, legacyKey);
                    return {
                        success: true,
                        decryptedText: new TextDecoder().decode(decryptedBytes),
                        keyAlias: `${alias} (Legacy Fernet)`,
                        cipher: "Fernet-128"
                    };
                }
            } catch (e) {
                continue;
            }
        }

        return {
            success: false,
            decryptedText: "",
            keyAlias: "",
            error: "Decryption failed: Incorrect password, keyfile, or corrupted ciphertext."
        };
    }

    // =========================================================================
    // File Encryption & Decryption (ENC5F\x02 & ENC4F\x01)
    // =========================================================================

    async function encryptFileBytes(fileBytes, password, keyType = "Key 4", progressCb = null, keyfileBytes = null, filename = "file.dat") {
        if (typeof progressCb === "function") progressCb(15, "Initializing memory-hard key derivation...");
        const config = getKeyConfig(keyType);
        const cryptoInstance = getCrypto();
        const salt = cryptoInstance.getRandomValues(new Uint8Array(config.saltLength));
        const derivedKey = await deriveMasterKey(password, salt, config, keyfileBytes, 32);

        if (typeof progressCb === "function") progressCb(45, "Encrypting file data with AES-256-GCM AEAD...");
        const { nonce, ciphertext } = await encryptAesGcm(fileBytes, derivedKey);

        if (typeof progressCb === "function") progressCb(80, "Assembling quantum-resistant ENC5F container...");
        const metadata = {
            v: 2,
            kdf: "scrypt",
            cipher: "AES-256-GCM",
            alias: config.alias,
            salt: toBase64Url(salt, true),
            nonce: toBase64Url(nonce, true),
            has_keyfile: Boolean(keyfileBytes && keyfileBytes.length > 0),
            orig_name: filename,
            size: fileBytes.length
        };
        const metaBytes = new TextEncoder().encode(JSON.stringify(metadata));

        const totalSize = 6 + 4 + metaBytes.length + ciphertext.length;
        const out = new Uint8Array(totalSize);
        out.set(FILE_MAGIC_V5, 0);

        const view = new DataView(out.buffer);
        view.setUint32(6, metaBytes.length, false);
        out.set(metaBytes, 10);
        out.set(ciphertext, 10 + metaBytes.length);

        if (typeof progressCb === "function") progressCb(100, "File encryption complete!");
        return out;
    }

    async function decryptFileBytes(fileBytes, password, fallbackKey = "Key 4", progressCb = null, keyfileBytes = null) {
        if (typeof progressCb === "function") progressCb(10, "Inspecting container header...");

        let isV5 = false;
        let isV4 = false;

        if (fileBytes.length >= 6) {
            isV5 = true;
            for (let i = 0; i < 6; i++) {
                if (fileBytes[i] !== FILE_MAGIC_V5[i]) { isV5 = false; break; }
            }
            if (!isV5) {
                isV4 = true;
                for (let i = 0; i < 6; i++) {
                    if (fileBytes[i] !== FILE_MAGIC_V4[i]) { isV4 = false; break; }
                }
            }
        }

        if (isV5) {
            if (fileBytes.length < 10) throw new Error('Corrupted ENC5F container');
            const view = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength);
            const metaLen = view.getUint32(6, false);
            const metaBytes = fileBytes.subarray(10, 10 + metaLen);
            const metadata = JSON.parse(new TextDecoder().decode(metaBytes));

            if (metadata.has_keyfile && (!keyfileBytes || keyfileBytes.length === 0)) {
                throw new Error("This file requires a Keyfile for decryption.");
            }

            const salt = fromBase64Url(metadata.salt);
            const nonce = fromBase64Url(metadata.nonce);
            const cipherBytes = fileBytes.subarray(10 + metaLen);
            const config = getKeyConfig(metadata.alias || fallbackKey);

            if (typeof progressCb === "function") progressCb(40, `Computing memory-hard key (${config.alias})...`);
            const derivedKey = await deriveMasterKey(password, salt, config, keyfileBytes, 32);

            if (typeof progressCb === "function") progressCb(75, "Authenticating AEAD payload...");
            const decryptedBytes = await decryptAesGcm(cipherBytes, derivedKey, nonce);

            if (typeof progressCb === "function") progressCb(100, "File decryption complete!");
            return {
                success: true,
                decryptedBytes: decryptedBytes,
                keyAlias: metadata.alias || config.alias,
                origName: metadata.orig_name || "decrypted_file"
            };
        } else if (isV4) {
            // Legacy V4 Fernet container
            const view = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength);
            let offset = 6;
            const aliasLen = view.getUint16(offset, false);
            offset += 2;
            const alias = new TextDecoder().decode(fileBytes.subarray(offset, offset + aliasLen));
            offset += aliasLen;

            const saltLen = view.getUint16(offset, false);
            offset += 2;
            const salt = fileBytes.subarray(offset, offset + saltLen);
            offset += saltLen;

            const fernetTokenBytes = fileBytes.subarray(offset);
            const iters = LEGACY_PBKDF2_MAP[alias] || 200000;

            if (typeof progressCb === "function") progressCb(45, `Deriving legacy key for ${alias}...`);
            const legacyKey = await pbkdf2Sha256(new TextEncoder().encode(password), salt, iters, 32);

            if (typeof progressCb === "function") progressCb(75, "Verifying HMAC signature...");
            const decryptedBytes = await decryptFernetToken(fernetTokenBytes, legacyKey);

            if (typeof progressCb === "function") progressCb(100, "File decryption complete!");
            return {
                success: true,
                decryptedBytes: decryptedBytes,
                keyAlias: `${alias} (Legacy)`,
                origName: "decrypted_file"
            };
        } else {
            // Fallback probe
            const config = getKeyConfig(fallbackKey);
            const salt = fileBytes.subarray(0, config.saltLength);
            const cipherBytes = fileBytes.subarray(config.saltLength);
            const iters = LEGACY_PBKDF2_MAP[fallbackKey] || 200000;
            const legacyKey = await pbkdf2Sha256(new TextEncoder().encode(password), salt, iters, 32);
            const decryptedBytes = await decryptFernetToken(cipherBytes, legacyKey);
            return {
                success: true,
                decryptedBytes: decryptedBytes,
                keyAlias: `${config.alias} (Legacy)`,
                origName: "decrypted_file"
            };
        }
    }

    // =========================================================================
    // Zlib & QR Helpers
    // =========================================================================

    async function compressZlib(str) {
        if (typeof CompressionStream !== 'undefined') {
            try {
                const stream = new Blob([new TextEncoder().encode(str)]).stream().pipeThrough(new CompressionStream('deflate'));
                const res = await new Response(stream).arrayBuffer();
                return toBase64Url(new Uint8Array(res), false);
            } catch (e) {}
        }
        return toBase64Url(new TextEncoder().encode(str), false);
    }

    async function decompressZlib(base64Str) {
        const bytes = fromBase64Url(base64Str);
        if (typeof DecompressionStream !== 'undefined') {
            try {
                const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
                const res = await new Response(stream).arrayBuffer();
                return new TextDecoder().decode(res);
            } catch (e) {}
        }
        return new TextDecoder().decode(bytes);
    }

    async function normalizeScannedText(text) {
        if (!text) return "";
        const s = text.trim();
        try {
            const decompressed = await decompressZlib(s);
            if (decompressed && (decompressed.startsWith(MAGIC_HEADER_V5) || decompressed.startsWith(MAGIC_HEADER_V4) || decompressed.length > 20)) {
                return decompressed;
            }
        } catch (e) {}
        return s;
    }

    // =========================================================================
    // Diceware & High-Entropy Password / Passphrase Generator
    // =========================================================================

    const DICEWARE_WORDS = [
        "quantum", "cipher", "matrix", "falcon", "beacon", "galaxy", "nebula", "aurora",
        "shield", "vertex", "vector", "orbital", "stellar", "photon", "pulsar", "cosmos",
        "crypto", "zenith", "vortex", "plasma", "shadow", "silver", "golden", "glacier",
        "castle", "island", "forest", "timber", "canyon", "desert", "stream", "summit",
        "thunder", "blizzard", "tornado", "typhoon", "volcano", "horizon", "eclipse", "comet",
        "bastion", "citadel", "fortress", "paladin", "sentinel", "guardian", "titan", "phoenix",
        "dragon", "hydra", "chimera", "pegasus", "kraken", "griffin", "sphinx", "valkyrie",
        "diamond", "emerald", "sapphire", "obsidian", "crystal", "granite", "basalt", "quartz",
        "anchor", "compass", "voyage", "odyssey", "pioneer", "explorer", "journey", "passage",
        "whisper", "echo", "harmony", "symphony", "melody", "rhythm", "tempo", "chorus",
        "radiant", "luminous", "brilliant", "infinite", "eternal", "serene", "tranquil", "valiant"
    ];

    function generateDicewarePassphrase(wordCount = 6, separator = "-") {
        const cryptoInstance = getCrypto();
        const randArray = new Uint32Array(wordCount);
        cryptoInstance.getRandomValues(randArray);
        const words = [];
        for (let i = 0; i < wordCount; i++) {
            words.push(DICEWARE_WORDS[randArray[i] % DICEWARE_WORDS.length]);
        }
        return words.join(separator);
    }

    function generateSecurePassword(length = 32, includeSymbols = true) {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        if (includeSymbols) {
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?";
        }
        const cryptoInstance = getCrypto();
        const randBuffer = new Uint32Array(length);
        cryptoInstance.getRandomValues(randBuffer);
        let res = "";
        for (let i = 0; i < length; i++) {
            res += chars[randBuffer[i] % chars.length];
        }
        return res;
    }

    function evaluatePassword(password, isMemoryHard = true) {
        if (!password) {
            return {
                score: 0,
                label: "None",
                color: "#64748b",
                entropy: 0.0,
                percent: 0,
                crackTime: "Instant"
            };
        }

        const length = password.length;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /\d/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);

        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSymbol) poolSize += 33;
        if (poolSize === 0) poolSize = 1;

        let entropy = length * Math.log2(poolSize);

        if (/(.)\1{2,}/.test(password)) entropy -= 12;
        if (/^[0-9]+$/.test(password) || /^[a-zA-Z]+$/.test(password)) entropy -= 10;

        entropy = Math.max(0.0, Math.round(entropy * 10) / 10);

        let score, label, color, percent;
        if (entropy < 40) {
            score = 1; label = "Weak"; color = "#ef4444"; percent = 25;
        } else if (entropy < 65) {
            score = 2; label = "Moderate"; color = "#f97316"; percent = 50;
        } else if (entropy < 90) {
            score = 3; label = "Strong"; color = "#eab308"; percent = 75;
        } else if (entropy < 120) {
            score = 4; label = "Very Strong"; color = "#22c55e"; percent = 90;
        } else {
            score = 5; label = "Vault Grade"; color = "#06b6d4"; percent = 100;
        }

        const hashRate = isMemoryHard ? 1e4 : 2e10;
        const combinations = Math.pow(2, entropy);
        const seconds = combinations / (2 * hashRate);

        let crackTime = "Instant";
        if (seconds < 1) crackTime = "< 1 second";
        else if (seconds < 60) crackTime = `${Math.round(seconds)} seconds`;
        else if (seconds < 3600) crackTime = `${Math.round(seconds / 60)} minutes`;
        else if (seconds < 86400) crackTime = `${Math.round(seconds / 3600)} hours`;
        else if (seconds < 31536000) crackTime = `${Math.round(seconds / 86400)} days`;
        else if (seconds < 31536000 * 100) crackTime = `${Math.round(seconds / 31536000)} years`;
        else if (seconds < 31536000 * 1e6) crackTime = `${Math.round(seconds / (31536000 * 1000))} Millennia`;
        else crackTime = "Billions of Years (Physically Impenetrable)";

        return { score, label, color, entropy, percent, crackTime };
    }

    return {
        MAGIC_HEADER_V5,
        MAGIC_HEADER_V4,
        FILE_MAGIC_V5,
        FILE_MAGIC_V4,
        KEY_CONFIGS,
        LEGACY_PBKDF2_MAP,
        getKeyConfig,
        toBase64Url,
        fromBase64Url,
        sha256,
        prepareKeyMaterial,
        deriveMasterKey,
        deriveScrypt,
        encryptAesGcm,
        decryptAesGcm,
        encryptText,
        decryptText,
        encryptFileBytes,
        decryptFileBytes,
        compressZlib,
        decompressZlib,
        normalizeScannedText,
        evaluatePassword,
        generateSecurePassword,
        generateDicewarePassphrase
    };
}));
