package com.example.crypto

data class DetectedFormat(
    val formatName: String,
    val isEncrypted: Boolean,
    val suggestedProfile: KeyProfile? = null,
    val confidenceBadge: String = "",
    val details: String = ""
)

object CipherFormatDetector {
    fun analyze(input: String): DetectedFormat {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) {
            return DetectedFormat(
                formatName = "Empty",
                isEncrypted = false,
                details = "No content provided"
            )
        }

        // 1. Next-Gen ENC5 Envelope format
        if (trimmed.startsWith("ENC5:")) {
            val parts = trimmed.split(":", limit = 6)
            if (parts.size == 6) {
                val alias = parts[1]
                val kdfTag = parts[2]
                val profile = KeyProfile.fromAlias(alias)
                return DetectedFormat(
                    formatName = "ENC5 Memory-Hard AEAD Envelope",
                    isEncrypted = true,
                    suggestedProfile = profile,
                    confidenceBadge = "Auto-Profile: ${profile.alias}",
                    details = "AES-256-GCM + ${kdfTag.uppercase()} (${profile.memoryMb}MB RAM   GPU-Proof)"
                )
            }
        }

        // 2. Legacy ENC4 Envelope format
        if (trimmed.startsWith("ENC4:")) {
            val parts = trimmed.split(":", limit = 4)
            if (parts.size == 4) {
                val alias = parts[1]
                val profile = KeyProfile.fromAlias(alias)
                return DetectedFormat(
                    formatName = "ENC4 Legacy Authenticated Envelope",
                    isEncrypted = true,
                    suggestedProfile = profile,
                    confidenceBadge = "Legacy PBKDF2: ${profile.alias}",
                    details = "Detected ${profile.alias} (${profile.legacyIterations / 1000}k iters, ${profile.saltLength}B salt)"
                )
            }
        }

        // 3. Check for Zlib compressed QR payload
        try {
            val decompressed = FernetCrypto.normalizeQrPayload(trimmed)
            if (decompressed != trimmed) {
                if (decompressed.startsWith("ENC5:")) {
                    val parts = decompressed.split(":", limit = 6)
                    val alias = parts.getOrNull(1) ?: "Key 4"
                    val profile = KeyProfile.fromAlias(alias)
                    return DetectedFormat(
                        formatName = "Compressed ENC5 QR Envelope",
                        isEncrypted = true,
                        suggestedProfile = profile,
                        confidenceBadge = "Zlib Deflate",
                        details = "Decompressed to ENC5 with ${profile.alias}"
                    )
                } else if (decompressed.startsWith("ENC4:")) {
                    val parts = decompressed.split(":", limit = 4)
                    val alias = parts.getOrNull(1) ?: "Key 2"
                    val profile = KeyProfile.fromAlias(alias)
                    return DetectedFormat(
                        formatName = "Compressed ENC4 QR Envelope",
                        isEncrypted = true,
                        suggestedProfile = profile,
                        confidenceBadge = "Zlib Deflate",
                        details = "Decompressed to Legacy ENC4 with ${profile.alias}"
                    )
                }
            }
        } catch (_: Exception) {}

        // 4. Raw Fernet token
        if (trimmed.startsWith("gAAAAA") && trimmed.length >= 80) {
            return DetectedFormat(
                formatName = "Legacy Fernet Token",
                isEncrypted = true,
                suggestedProfile = null,
                confidenceBadge = "Fernet v0x80",
                details = "Legacy Python / EncDec Fernet ciphertext (AES-128-CBC + HMAC-SHA256)"
            )
        }

        // 5. Encrypted Binary / Base64 AEAD
        if (trimmed.length > 80 && trimmed.matches(Regex("^[A-Za-z0-9_-]+={0,2}$"))) {
            return DetectedFormat(
                formatName = "Encrypted Binary / AEAD Payload",
                isEncrypted = true,
                suggestedProfile = null,
                confidenceBadge = "Base64URL",
                details = "Raw salt + nonce + AES-256-GCM ciphertext"
            )
        }

        return DetectedFormat(
            formatName = "Plaintext",
            isEncrypted = false,
            suggestedProfile = null,
            confidenceBadge = "UTF-8",
            details = "${trimmed.length} characters"
        )
    }
}
