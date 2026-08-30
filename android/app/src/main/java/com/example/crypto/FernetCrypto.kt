package com.example.crypto

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.Deflater
import java.util.zip.Inflater
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class DecryptionResult(
    val decryptedText: String,
    val keyProfile: KeyProfile,
    val wasEnvelope: Boolean,
    val cipherEngine: String = "AES-256-GCM (scrypt)"
)

data class VaultFileEntry(
    val name: String,
    val size: Long,
    val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as VaultFileEntry
        return name == other.name && size == other.size && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        var result = name.hashCode()
        result = 31 * result + size.hashCode()
        result = 31 * result + bytes.contentHashCode()
        return result
    }
}

object FernetCrypto {
    const val MAGIC_HEADER_V5 = "ENC5:"
    const val MAGIC_HEADER_V4 = "ENC4:"
    val FILE_MAGIC_V5 = byteArrayOf('E'.code.toByte(), 'N'.code.toByte(), 'C'.code.toByte(), '5'.code.toByte(), 'F'.code.toByte(), 0x02)
    val FILE_MAGIC_V4 = byteArrayOf('E'.code.toByte(), 'N'.code.toByte(), 'C'.code.toByte(), '4'.code.toByte(), 'F'.code.toByte(), 0x01)

    private val secureRandom = SecureRandom()

    fun b64UrlEncode(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun b64UrlDecode(str: String): ByteArray {
        val clean = str.trim()
        return Base64.decode(clean, Base64.URL_SAFE or Base64.DEFAULT)
    }

    fun prepareKeyMaterial(password: String, keyfileBytes: ByteArray? = null): ByteArray {
        val passBytes = password.toByteArray(Charsets.UTF_8)
        return if (keyfileBytes != null && keyfileBytes.isNotEmpty()) {
            val md = MessageDigest.getInstance("SHA-256")
            val kfHash = md.digest(keyfileBytes)
            val separator = "::KEYFILE::".toByteArray(Charsets.UTF_8)
            val buffer = ByteBuffer.allocate(passBytes.size + separator.size + kfHash.size)
            buffer.put(passBytes)
            buffer.put(separator)
            buffer.put(kfHash)
            buffer.array()
        } else {
            passBytes
        }
    }

    fun deriveKey(passwordMaterial: String, salt: ByteArray, profile: KeyProfile, keyfileBytes: ByteArray? = null): ByteArray {
        val material = prepareKeyMaterial(passwordMaterial, keyfileBytes)
        return deriveKey(material, salt, profile)
    }

    fun deriveKey(material: ByteArray, salt: ByteArray, profile: KeyProfile): ByteArray {
        return Scrypt.scrypt(
            password = material,
            salt = salt,
            N = profile.scryptN,
            r = profile.scryptR,
            p = profile.scryptP,
            dkLen = 32
        )
    }

    fun deriveLegacyPbkdf2(password: String, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    fun encryptGcm(plaintext: ByteArray, key32: ByteArray): Pair<ByteArray, ByteArray> {
        require(key32.size == 32) { "AES-256 key must be 32 bytes" }
        val nonce = ByteArray(12).apply { secureRandom.nextBytes(this) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        return Pair(nonce, ciphertext)
    }

    fun decryptGcm(ciphertextWithTag: ByteArray, nonce: ByteArray, key32: ByteArray): ByteArray {
        require(key32.size == 32) { "AES-256 key must be 32 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertextWithTag)
    }

    fun encryptText(
        plainText: String,
        password: String,
        profile: KeyProfile,
        keyfileBytes: ByteArray? = null,
        useEnvelope: Boolean = true
    ): String {
        require(plainText.isNotEmpty()) { "Plaintext cannot be empty" }
        require(password.isNotEmpty()) { "Password is required" }

        val salt = ByteArray(profile.saltLength).apply { secureRandom.nextBytes(this) }
        val material = prepareKeyMaterial(password, keyfileBytes)
        val key = deriveKey(material, salt, profile)
        val (nonce, ciphertext) = encryptGcm(plainText.toByteArray(Charsets.UTF_8), key)

        return if (useEnvelope) {
            val saltB64 = b64UrlEncode(salt)
            val nonceB64 = b64UrlEncode(nonce)
            val cipherB64 = b64UrlEncode(ciphertext)
            "$MAGIC_HEADER_V5${profile.alias}:scrypt:$saltB64:$nonceB64:$cipherB64"
        } else {
            val combined = ByteBuffer.allocate(salt.size + nonce.size + ciphertext.size).apply {
                put(salt)
                put(nonce)
                put(ciphertext)
            }.array()
            b64UrlEncode(combined)
        }
    }

    fun decryptText(
        cipherInput: String,
        password: String,
        selectedProfile: KeyProfile = KeyProfile.DEFAULT,
        keyfileBytes: ByteArray? = null
    ): DecryptionResult {
        require(cipherInput.isNotBlank()) { "Ciphertext cannot be empty" }
        require(password.isNotEmpty()) { "Password is required" }

        val rawInput = normalizeQrPayload(cipherInput.trim())
        val material = prepareKeyMaterial(password, keyfileBytes)

        // 1. Next-Gen ENC5 Format
        if (rawInput.startsWith(MAGIC_HEADER_V5)) {
            val parts = rawInput.split(":", limit = 6)
            if (parts.size == 6) {
                val alias = parts[1]
                val kdfTag = parts[2]
                val saltB64 = parts[3]
                val nonceB64 = parts[4]
                val cipherB64 = parts[5]
                val profile = KeyProfile.fromAlias(alias)
                val salt = b64UrlDecode(saltB64)
                val nonce = b64UrlDecode(nonceB64)
                val ciphertext = b64UrlDecode(cipherB64)
                val key = deriveKey(material, salt, profile)
                val decryptedBytes = decryptGcm(ciphertext, nonce, key)
                return DecryptionResult(
                    decryptedText = String(decryptedBytes, Charsets.UTF_8),
                    keyProfile = profile,
                    wasEnvelope = true,
                    cipherEngine = "AES-256-GCM ($kdfTag)"
                )
            }
        }

        // 2. Legacy ENC4 Format
        if (rawInput.startsWith(MAGIC_HEADER_V4)) {
            val parts = rawInput.split(":", limit = 4)
            if (parts.size == 4) {
                val alias = parts[1]
                val saltB64 = parts[2]
                val tokenB64 = parts[3]
                val profile = KeyProfile.fromAlias(alias)
                val salt = b64UrlDecode(saltB64)
                val key = deriveLegacyPbkdf2(password, salt, profile.legacyIterations)
                val decryptedBytes = decryptFernet(tokenB64, key)
                return DecryptionResult(
                    decryptedText = String(decryptedBytes, Charsets.UTF_8),
                    keyProfile = profile,
                    wasEnvelope = true,
                    cipherEngine = "Legacy Fernet-128 (PBKDF2)"
                )
            }
        }

        // 3. Probe AES-256-GCM raw payload
        for (profile in KeyProfile.ALL_PROFILES) {
            try {
                val rawBytes = b64UrlDecode(rawInput)
                val minLen = profile.saltLength + 12 + 16
                if (rawBytes.size > minLen) {
                    val salt = rawBytes.copyOfRange(0, profile.saltLength)
                    val nonce = rawBytes.copyOfRange(profile.saltLength, profile.saltLength + 12)
                    val ciphertext = rawBytes.copyOfRange(profile.saltLength + 12, rawBytes.size)
                    val key = deriveKey(material, salt, profile)
                    val decryptedBytes = decryptGcm(ciphertext, nonce, key)
                    return DecryptionResult(
                        decryptedText = String(decryptedBytes, Charsets.UTF_8),
                        keyProfile = profile,
                        wasEnvelope = false,
                        cipherEngine = "AES-256-GCM (scrypt)"
                    )
                }
            } catch (_: Exception) {
                continue
            }
        }

        // 4. Legacy Fallback
        for (profile in KeyProfile.ALL_PROFILES) {
            try {
                val rawBytes = b64UrlDecode(rawInput)
                if (rawBytes.size > profile.saltLength + 73) {
                    val salt = rawBytes.copyOfRange(0, profile.saltLength)
                    val tokenBytes = rawBytes.copyOfRange(profile.saltLength, rawBytes.size)
                    val key = deriveLegacyPbkdf2(password, salt, profile.legacyIterations)
                    val decryptedBytes = decryptFernet(b64UrlEncode(tokenBytes), key)
                    return DecryptionResult(
                        decryptedText = String(decryptedBytes, Charsets.UTF_8),
                        keyProfile = profile,
                        wasEnvelope = false,
                        cipherEngine = "Legacy Fernet-128 (PBKDF2)"
                    )
                }
            } catch (_: Exception) {
                continue
            }
        }

        throw SecurityException("Decryption failed. Please check password, keyfile, or ciphertext integrity.")
    }

    fun encryptFernet(plaintext: ByteArray, key32: ByteArray): String {
        require(key32.size == 32) { "Fernet key must be 32 bytes" }
        val signingKey = key32.copyOfRange(0, 16)
        val encryptionKey = key32.copyOfRange(16, 32)
        val iv = ByteArray(16).apply { secureRandom.nextBytes(this) }
        val timestamp = System.currentTimeMillis() / 1000L
        val tsBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(timestamp).array()
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), IvParameterSpec(iv))
        val ciphertext = cipher.doFinal(plaintext)
        val payload = ByteBuffer.allocate(1 + 8 + 16 + ciphertext.size).apply {
            put(0x80.toByte())
            put(tsBytes)
            put(iv)
            put(ciphertext)
        }.array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingKey, "HmacSHA256"))
        val hmac = mac.doFinal(payload)
        val token = ByteBuffer.allocate(payload.size + 32).apply {
            put(payload)
            put(hmac)
        }.array()
        return b64UrlEncode(token)
    }

    fun decryptFernet(tokenB64: String, key32: ByteArray): ByteArray {
        val token = b64UrlDecode(tokenB64)
        if (token.size < 73) throw IllegalArgumentException("Token too short (< 73 bytes)")
        if (token[0] != 0x80.toByte()) throw IllegalArgumentException("Invalid Fernet token version")
        val signingKey = key32.copyOfRange(0, 16)
        val encryptionKey = key32.copyOfRange(16, 32)
        val payloadSize = token.size - 32
        val payload = token.copyOfRange(0, payloadSize)
        val receivedHmac = token.copyOfRange(payloadSize, token.size)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingKey, "HmacSHA256"))
        val computedHmac = mac.doFinal(payload)
        if (!MessageDigest.isEqual(computedHmac, receivedHmac)) {
            throw SecurityException("Authentication verification failed (Invalid password or corrupted data)")
        }
        val iv = payload.copyOfRange(9, 25)
        val ciphertext = payload.copyOfRange(25, payload.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(ciphertext)
    }

    fun encryptFile(
        fileBytes: ByteArray,
        password: String,
        profile: KeyProfile,
        keyfileBytes: ByteArray? = null,
        origName: String = "file"
    ): ByteArray {
        val salt = ByteArray(profile.saltLength).apply { secureRandom.nextBytes(this) }
        val material = prepareKeyMaterial(password, keyfileBytes)
        val key = deriveKey(material, salt, profile)
        val (nonce, ciphertext) = encryptGcm(fileBytes, key)

        val metaJson = JSONObject().apply {
            put("v", 2)
            put("kdf", "scrypt")
            put("cipher", "AES-256-GCM")
            put("alias", profile.alias)
            put("salt", b64UrlEncode(salt))
            put("nonce", b64UrlEncode(nonce))
            put("has_keyfile", keyfileBytes != null && keyfileBytes.isNotEmpty())
            put("orig_name", origName)
            put("size", fileBytes.size)
        }
        val metaBytes = metaJson.toString().toByteArray(Charsets.UTF_8)

        val buffer = ByteBuffer.allocate(
            FILE_MAGIC_V5.size + 4 + metaBytes.size + ciphertext.size
        ).order(ByteOrder.BIG_ENDIAN)
        buffer.put(FILE_MAGIC_V5)
        buffer.putInt(metaBytes.size)
        buffer.put(metaBytes)
        buffer.put(ciphertext)
        return buffer.array()
    }

    fun encryptFileStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        password: String,
        profile: KeyProfile,
        keyfileBytes: ByteArray? = null,
        origName: String = "file",
        totalBytes: Long = 0L,
        onProgress: ((Float) -> Unit)? = null
    ) {
        val allBytes = inputStream.readBytes()
        val enc = encryptFile(allBytes, password, profile, keyfileBytes, origName)
        outputStream.write(enc)
        outputStream.flush()
        onProgress?.invoke(1.0f)
    }

    fun decryptFile(
        containerBytes: ByteArray,
        password: String,
        keyfileBytes: ByteArray? = null,
        defaultProfile: KeyProfile = KeyProfile.DEFAULT
    ): Pair<ByteArray, KeyProfile> {
        val material = prepareKeyMaterial(password, keyfileBytes)

        val isV5 = containerBytes.size >= FILE_MAGIC_V5.size &&
                (0 until FILE_MAGIC_V5.size).all { containerBytes[it] == FILE_MAGIC_V5[it] }

        if (isV5) {
            val buffer = ByteBuffer.wrap(containerBytes).order(ByteOrder.BIG_ENDIAN)
            buffer.position(FILE_MAGIC_V5.size)
            val metaLen = buffer.int
            if (metaLen <= 0 || metaLen > containerBytes.size - FILE_MAGIC_V5.size - 4) {
                throw IllegalArgumentException("Corrupted ENC5F container metadata")
            }
            val metaBytes = ByteArray(metaLen)
            buffer.get(metaBytes)
            val metaJson = JSONObject(String(metaBytes, Charsets.UTF_8))
            val alias = metaJson.optString("alias", "Key 4")
            val profile = KeyProfile.fromAlias(alias)
            val salt = b64UrlDecode(metaJson.getString("salt"))
            val nonce = b64UrlDecode(metaJson.getString("nonce"))
            val hasKeyfile = metaJson.optBoolean("has_keyfile", false)

            if (hasKeyfile && (keyfileBytes == null || keyfileBytes.isEmpty())) {
                throw IllegalArgumentException("This container requires a 2FA Keyfile to decrypt.")
            }

            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)
            val key = deriveKey(material, salt, profile)
            val decrypted = decryptGcm(ciphertext, nonce, key)
            return Pair(decrypted, profile)
        }

        val isV4 = containerBytes.size >= FILE_MAGIC_V4.size &&
                (0 until FILE_MAGIC_V4.size).all { containerBytes[it] == FILE_MAGIC_V4[it] }

        if (isV4) {
            val buffer = ByteBuffer.wrap(containerBytes).order(ByteOrder.BIG_ENDIAN)
            buffer.position(FILE_MAGIC_V4.size)
            val aliasLen = buffer.get().toInt() and 0xFF
            val aliasBytes = ByteArray(aliasLen)
            buffer.get(aliasBytes)
            val alias = String(aliasBytes, Charsets.UTF_8)
            val profile = KeyProfile.fromAlias(alias)
            val saltLen = buffer.short.toInt() and 0xFFFF
            val salt = ByteArray(saltLen)
            buffer.get(salt)
            val tokenRaw = ByteArray(buffer.remaining())
            buffer.get(tokenRaw)
            val key = deriveLegacyPbkdf2(password, salt, profile.legacyIterations)
            val decrypted = decryptFernet(b64UrlEncode(tokenRaw), key)
            return Pair(decrypted, profile)
        }

        throw IllegalArgumentException("Invalid file format. Not a recognized EncDec container (ENC5F / ENC4F).")
    }

    fun decryptFileStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        password: String,
        keyfileBytes: ByteArray? = null,
        totalBytes: Long = 0L,
        onProgress: ((Float) -> Unit)? = null
    ): KeyProfile {
        val containerBytes = inputStream.readBytes()
        val (decrypted, profile) = decryptFile(containerBytes, password, keyfileBytes)
        outputStream.write(decrypted)
        outputStream.flush()
        onProgress?.invoke(1.0f)
        return profile
    }

    fun createZipArchive(files: List<VaultFileEntry>): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { zos ->
            for (file in files) {
                val entry = ZipEntry(file.name)
                zos.putNextEntry(entry)
                zos.write(file.bytes)
                zos.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    fun extractZipArchive(zipBytes: ByteArray): List<VaultFileEntry> {
        val list = mutableListOf<VaultFileEntry>()
        ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
            var entry: ZipEntry? = zis.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val entryBytes = zis.readBytes()
                    list.add(
                        VaultFileEntry(
                            name = entry.name,
                            size = entryBytes.size.toLong(),
                            bytes = entryBytes
                        )
                    )
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
        return list
    }

    fun compressZlib(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        deflater.setInput(data)
        deflater.finish()
        val outputStream = ByteArrayOutputStream(data.size)
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer)
            outputStream.write(buffer, 0, count)
        }
        deflater.end()
        return outputStream.toByteArray()
    }

    fun decompressZlib(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        inflater.setInput(compressed)
        val outputStream = ByteArrayOutputStream(compressed.size * 2)
        val buffer = ByteArray(1024)
        while (!inflater.finished()) {
            val count = inflater.inflate(buffer)
            if (count == 0 && inflater.needsInput()) break
            outputStream.write(buffer, 0, count)
        }
        inflater.end()
        return outputStream.toByteArray()
    }

    fun normalizeQrPayload(payload: String): String {
        val trimmed = payload.trim()
        if (trimmed.isEmpty()) return trimmed
        return try {
            val raw = b64UrlDecode(trimmed)
            val decompressed = decompressZlib(raw)
            String(decompressed, Charsets.UTF_8)
        } catch (_: Exception) {
            trimmed
        }
    }
}
