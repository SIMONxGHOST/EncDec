package com.example.crypto

data class KeyProfile(
    val id: String,
    val alias: String,
    val saltLength: Int,
    val memoryMb: Int,
    val scryptN: Int,
    val scryptR: Int = 8,
    val scryptP: Int = 1,
    val legacyIterations: Int,
    val rating: String,
    val description: String,
    val cipher: String = "AES-256-GCM",
    val badgeColorHex: Long = 0xFF38BDF8
) {
    val iterations: Int get() = legacyIterations

    companion object {
        val ALL_PROFILES = listOf(
            KeyProfile("Key 1", "Key 1", 32, 16, 16384, 8, 1, 100_000, "Fast", "16MB RAM   Fast Memory-Hard", "AES-256-GCM", 0xFF10B981),
            KeyProfile("Key 2", "Key 2", 32, 32, 32768, 8, 1, 200_000, "Standard", "32MB RAM   Standard Vault", "AES-256-GCM", 0xFF22C55E),
            KeyProfile("Key 3", "Key 3", 32, 48, 32768, 12, 1, 300_000, "Enhanced", "48MB RAM   Enhanced Security", "AES-256-GCM", 0xFF38BDF8),
            KeyProfile("Key 4", "Key 4", 32, 64, 65536, 8, 1, 400_000, "High", "64MB RAM   High Security AEAD", "AES-256-GCM", 0xFF6366F1),
            KeyProfile("Key 5", "Key 5", 32, 96, 65536, 12, 1, 500_000, "High+", "96MB RAM   High+ Vault Grade", "AES-256-GCM", 0xFF818CF8),
            KeyProfile("Key 6", "Key 6", 32, 128, 131072, 8, 1, 800_000, "Strong", "128MB RAM   Strong Vault Grade", "AES-256-GCM", 0xFFA855F7),
            KeyProfile("Key 7", "Key 7", 32, 160, 131072, 10, 1, 1_000_000, "Very Strong", "160MB RAM   Very Strong Vault", "AES-256-GCM", 0xFFC084FC),
            KeyProfile("Key 8", "Key 8", 32, 192, 131072, 12, 1, 1_200_000, "Ultra", "192MB RAM   Supercomputer-Proof", "AES-256-GCM", 0xFFF43F5E),
            KeyProfile("Key 9", "Key 9", 32, 256, 262144, 8, 1, 1_500_000, "Extreme", "256MB RAM   Military Vault Grade", "AES-256-GCM", 0xFFF59E0B),
            KeyProfile("Key 10", "Key 10", 32, 512, 524288, 8, 1, 2_000_000, "Paranoid", "512MB RAM   Quantum / ASIC Proof", "AES-256-GCM", 0xFFEF4444)
        )

        val DEFAULT = ALL_PROFILES[3] // Key 4 (High - 64MB)

        fun fromAlias(name: String): KeyProfile {
            val clean = name.trim().lowercase()
            return ALL_PROFILES.firstOrNull {
                it.alias.lowercase() == clean ||
                it.id.lowercase() == clean ||
                clean.contains(it.alias.lowercase()) ||
                (clean.contains("vault 10") && it.alias == "Key 10") ||
                (clean.contains("vault 9") && it.alias == "Key 9") ||
                (clean.contains("vault 8") && it.alias == "Key 8") ||
                (clean.contains("vault 7") && it.alias == "Key 7")
            } ?: DEFAULT
        }
    }
}
