package com.example.crypto

import java.security.SecureRandom
import kotlin.math.log2
import kotlin.math.pow

data class EntropyResult(
    val bits: Int,
    val poolSize: Int,
    val rating: String,
    val crackTimeEstimate: String,
    val scorePercentage: Float,
    val colorHex: Long
)

object PasswordEngine {
    private val random = SecureRandom()
    private const val UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    private const val NUMBERS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    private const val AMBIGUOUS = "l1IO0"

    val DICEWARE_WORDS = listOf(
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
        "radiant", "luminous", "brilliant", "infinite", "eternal", "serene", "tranquil", "valiant",
        "avalanche", "solstice", "meridian", "chronos", "spectrum", "prism", "tempest", "obsidian"
    )

    fun calculateEntropy(password: String): EntropyResult {
        if (password.isEmpty()) {
            return EntropyResult(0, 0, "None", "Instant", 0f, 0xFF64748B)
        }

        val isDiceware = password.contains("-") || password.contains("_") || password.contains(" ") || password.contains(".")
        val words = password.split(Regex("[-_ .]"))

        val entropy = if (isDiceware && words.size >= 3) {
            (words.size * 12.9).toInt()
        } else {
            var pool = 0
            if (password.any { it.isLowerCase() }) pool += 26
            if (password.any { it.isUpperCase() }) pool += 26
            if (password.any { it.isDigit() }) pool += 10
            if (password.any { !it.isLetterOrDigit() }) pool += 32
            if (pool == 0) pool = 10
            (password.length * log2(pool.toDouble())).toInt()
        }

        val score = (entropy / 128f).coerceIn(0f, 1f)
        val (rating, color) = when {
            entropy < 35 -> "Very Weak" to 0xFFEF4444
            entropy < 60 -> "Weak" to 0xFFF59E0B
            entropy < 80 -> "Moderate" to 0xFFEAB308
            entropy < 105 -> "Strong" to 0xFF10B981
            else -> "Supercomputer-Proof" to 0xFF38BDF8
        }

        val crackTime = estimateCrackTime(entropy)
        return EntropyResult(
            bits = entropy,
            poolSize = if (isDiceware) DICEWARE_WORDS.size else password.length,
            rating = rating,
            crackTimeEstimate = crackTime,
            scorePercentage = score,
            colorHex = color
        )
    }

    private fun estimateCrackTime(entropyBits: Int): String {
        val guesses = 2.0.pow(entropyBits.toDouble())
        val seconds = guesses / 1e11
        return when {
            seconds < 1 -> "Instant (< 1 sec)"
            seconds < 60 -> "${seconds.toInt()} seconds"
            seconds < 3600 -> "${(seconds / 60).toInt()} minutes"
            seconds < 86400 -> "${(seconds / 3600).toInt()} hours"
            seconds < 86400 * 365 -> "${(seconds / 86400).toInt()} days"
            seconds < 86400 * 365 * 100 -> "${(seconds / (86400 * 365)).toInt()} years"
            seconds < 86400 * 365 * 1_000_000 -> "${(seconds / (86400 * 365 * 1000)).toInt()}k years"
            else -> "Quantum / ASIC Proof (Centuries)"
        }
    }

    fun generateDiceware(
        wordCount: Int = 6,
        separator: String = "-"
    ): String {
        val count = wordCount.coerceIn(4, 10)
        val chosen = (0 until count).map {
            DICEWARE_WORDS[random.nextInt(DICEWARE_WORDS.size)]
        }
        return chosen.joinToString(separator)
    }

    fun generatePassword(
        length: Int = 32,
        includeUpper: Boolean = true,
        includeLower: Boolean = true,
        includeNumbers: Boolean = true,
        includeSymbols: Boolean = true,
        excludeAmbiguous: Boolean = true
    ): String {
        val pool = StringBuilder()
        val guaranteed = mutableListOf<Char>()
        var upperPool = UPPERCASE
        var lowerPool = LOWERCASE
        var numPool = NUMBERS
        var symPool = SYMBOLS

        if (excludeAmbiguous) {
            upperPool = upperPool.filter { it !in AMBIGUOUS }
            lowerPool = lowerPool.filter { it !in AMBIGUOUS }
            numPool = numPool.filter { it !in AMBIGUOUS }
            symPool = symPool.filter { it !in AMBIGUOUS }
        }

        if (includeUpper && upperPool.isNotEmpty()) {
            pool.append(upperPool)
            guaranteed.add(upperPool[random.nextInt(upperPool.length)])
        }
        if (includeLower && lowerPool.isNotEmpty()) {
            pool.append(lowerPool)
            guaranteed.add(lowerPool[random.nextInt(lowerPool.length)])
        }
        if (includeNumbers && numPool.isNotEmpty()) {
            pool.append(numPool)
            guaranteed.add(numPool[random.nextInt(numPool.length)])
        }
        if (includeSymbols && symPool.isNotEmpty()) {
            pool.append(symPool)
            guaranteed.add(symPool[random.nextInt(symPool.length)])
        }
        if (pool.isEmpty()) {
            pool.append(LOWERCASE)
            guaranteed.add(LOWERCASE[0])
        }

        val poolStr = pool.toString()
        val targetLen = length.coerceIn(8, 64)
        val result = CharArray(targetLen)
        for (i in guaranteed.indices) {
            if (i < targetLen) result[i] = guaranteed[i]
        }
        for (i in guaranteed.size until targetLen) {
            result[i] = poolStr[random.nextInt(poolStr.length)]
        }

        for (i in targetLen - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val temp = result[i]
            result[i] = result[j]
            result[j] = temp
        }
        return String(result)
    }
}
