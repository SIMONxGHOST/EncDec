package com.example.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure Kotlin implementation of RFC 7914 Scrypt Memory-Hard Key Derivation Function.
 * Designed to thwart GPU/ASIC cluster brute-force attacks via memory bandwidth throttling.
 */
object Scrypt {

    fun scrypt(
        password: ByteArray,
        salt: ByteArray,
        N: Int,
        r: Int,
        p: Int,
        dkLen: Int
    ): ByteArray {
        require(N > 1 && (N and (N - 1)) == 0) { "N must be a power of 2 greater than 1" }
        require(r > 0 && p > 0) { "Parameters r and p must be positive" }

        // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, 128 * r * p)
        val B = pbkdf2HmacSha256(password, salt, 1, 128 * r * p)

        // Step 2: For each block, B[i] = SMix(B[i], N, r)
        val bLen = 128 * r
        val block = IntArray(32 * r)
        val X = IntArray(32 * r)
        val Y = IntArray(32 * r)
        val V = Array(N) { IntArray(32 * r) }

        for (i in 0 until p) {
            bytesToLEInts(B, i * bLen, block, 0, 32 * r)
            smix(block, N, r, V, X, Y)
            leIntsToBytes(block, 0, B, i * bLen, 32 * r)
        }

        // Step 3: PBKDF2-HMAC-SHA256(password, B, 1, dkLen)
        return pbkdf2HmacSha256(password, B, 1, dkLen)
    }

    private fun smix(B: IntArray, N: Int, r: Int, V: Array<IntArray>, X: IntArray, Y: IntArray) {
        val len = 32 * r
        System.arraycopy(B, 0, X, 0, len)
        for (i in 0 until N) {
            System.arraycopy(X, 0, V[i], 0, len)
            blockmixSalsa8(X, Y, r)
            System.arraycopy(Y, 0, X, 0, len)
        }
        val mask = N - 1
        for (i in 0 until N) {
            val j = X[len - 16] and mask
            val Vj = V[j]
            for (k in 0 until len) {
                X[k] = X[k] xor Vj[k]
            }
            blockmixSalsa8(X, Y, r)
            System.arraycopy(Y, 0, X, 0, len)
        }
        System.arraycopy(X, 0, B, 0, len)
    }

    private fun blockmixSalsa8(B: IntArray, Y: IntArray, r: Int) {
        val X = IntArray(16)
        System.arraycopy(B, (2 * r - 1) * 16, X, 0, 16)
        for (i in 0 until 2 * r) {
            val offset = i * 16
            for (k in 0 until 16) {
                X[k] = X[k] xor B[offset + k]
            }
            salsa208(X)
            val destOffset = if (i % 2 == 0) {
                (i / 2) * 16
            } else {
                (r + (i - 1) / 2) * 16
            }
            System.arraycopy(X, 0, Y, destOffset, 16)
        }
    }

    private fun salsa208(B: IntArray) {
        val x = B.clone()
        for (i in 0 until 4) {
            // Column round
            x[4] = x[4] xor rotl(x[0] + x[12], 7)
            x[8] = x[8] xor rotl(x[4] + x[0], 9)
            x[12] = x[12] xor rotl(x[8] + x[4], 13)
            x[0] = x[0] xor rotl(x[12] + x[8], 18)
            x[9] = x[9] xor rotl(x[5] + x[1], 7)
            x[13] = x[13] xor rotl(x[9] + x[5], 9)
            x[1] = x[1] xor rotl(x[13] + x[9], 13)
            x[5] = x[5] xor rotl(x[1] + x[13], 18)
            x[14] = x[14] xor rotl(x[10] + x[6], 7)
            x[2] = x[2] xor rotl(x[14] + x[10], 9)
            x[6] = x[6] xor rotl(x[2] + x[14], 13)
            x[10] = x[10] xor rotl(x[6] + x[2], 18)
            x[3] = x[3] xor rotl(x[15] + x[11], 7)
            x[7] = x[7] xor rotl(x[3] + x[15], 9)
            x[11] = x[11] xor rotl(x[7] + x[3], 13)
            x[15] = x[15] xor rotl(x[11] + x[7], 18)

            // Row round
            x[1] = x[1] xor rotl(x[0] + x[3], 7)
            x[2] = x[2] xor rotl(x[1] + x[0], 9)
            x[3] = x[3] xor rotl(x[2] + x[1], 13)
            x[0] = x[0] xor rotl(x[3] + x[2], 18)
            x[6] = x[6] xor rotl(x[5] + x[4], 7)
            x[7] = x[7] xor rotl(x[6] + x[5], 9)
            x[4] = x[4] xor rotl(x[7] + x[6], 13)
            x[5] = x[5] xor rotl(x[4] + x[7], 18)
            x[11] = x[11] xor rotl(x[10] + x[9], 7)
            x[8] = x[8] xor rotl(x[11] + x[10], 9)
            x[9] = x[9] xor rotl(x[8] + x[11], 13)
            x[10] = x[10] xor rotl(x[9] + x[8], 18)
            x[12] = x[12] xor rotl(x[15] + x[14], 7)
            x[13] = x[13] xor rotl(x[12] + x[15], 9)
            x[14] = x[14] xor rotl(x[13] + x[12], 13)
            x[15] = x[15] xor rotl(x[14] + x[13], 18)
        }
        for (i in 0 until 16) {
            B[i] = B[i] + x[i]
        }
    }

    private fun rotl(a: Int, b: Int): Int = (a shl b) or (a ushr (32 - b))

    private fun bytesToLEInts(bytes: ByteArray, byteOffset: Int, ints: IntArray, intOffset: Int, intCount: Int) {
        for (i in 0 until intCount) {
            val bo = byteOffset + i * 4
            ints[intOffset + i] = (bytes[bo].toInt() and 0xFF) or
                    ((bytes[bo + 1].toInt() and 0xFF) shl 8) or
                    ((bytes[bo + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[bo + 3].toInt() and 0xFF) shl 24)
        }
    }

    private fun leIntsToBytes(ints: IntArray, intOffset: Int, bytes: ByteArray, byteOffset: Int, intCount: Int) {
        for (i in 0 until intCount) {
            val v = ints[intOffset + i]
            val bo = byteOffset + i * 4
            bytes[bo] = (v and 0xFF).toByte()
            bytes[bo + 1] = ((v ushr 8) and 0xFF).toByte()
            bytes[bo + 2] = ((v ushr 16) and 0xFF).toByte()
            bytes[bo + 3] = ((v ushr 24) and 0xFF).toByte()
        }
    }

    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val hLen = 32
        val l = (dkLen + hLen - 1) / hLen
        val r = dkLen - (l - 1) * hLen
        val result = ByteArray(dkLen)
        val u = ByteArray(hLen)
        val block = ByteArray(salt.size + 4)
        System.arraycopy(salt, 0, block, 0, salt.size)
        var pos = 0
        for (i in 1..l) {
            block[salt.size] = (i ushr 24).toByte()
            block[salt.size + 1] = (i ushr 16).toByte()
            block[salt.size + 2] = (i ushr 8).toByte()
            block[salt.size + 3] = i.toByte()
            mac.update(block)
            mac.doFinal(u, 0)
            val t = u.clone()
            for (iter in 1 until iterations) {
                mac.update(u)
                mac.doFinal(u, 0)
                for (k in 0 until hLen) {
                    t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
                }
            }
            val copyLen = if (i == l) r else hLen
            System.arraycopy(t, 0, result, pos, copyLen)
            pos += copyLen
        }
        return result
    }
}
