package com.example.crypto

import android.graphics.Bitmap
import android.graphics.Color
import java.nio.ByteBuffer
import java.nio.ByteOrder

object SteganographyEngine {
    private val MAGIC_HEADER = byteArrayOf('S'.code.toByte(), 'T'.code.toByte(), 'E'.code.toByte(), 'G'.code.toByte())

    fun calculateCapacity(width: Int, height: Int): Int {
        val totalBits = width.toLong() * height.toLong() * 3L
        val totalBytes = (totalBits / 8L).toInt()
        val overhead = MAGIC_HEADER.size + 4
        return (totalBytes - overhead).coerceAtLeast(0)
    }

    fun embedPayload(sourceBitmap: Bitmap, payload: String): Bitmap {
        val payloadBytes = payload.toByteArray(Charsets.UTF_8)
        val capacity = calculateCapacity(sourceBitmap.width, sourceBitmap.height)
        require(payloadBytes.size <= capacity) {
            "Payload too large (${payloadBytes.size} bytes). Image capacity is $capacity bytes. Use a larger image."
        }

        val buffer = ByteBuffer.allocate(MAGIC_HEADER.size + 4 + payloadBytes.size).order(ByteOrder.BIG_ENDIAN)
        buffer.put(MAGIC_HEADER)
        buffer.putInt(payloadBytes.size)
        buffer.put(payloadBytes)
        val fullData = buffer.array()

        val mutableBitmap = sourceBitmap.copy(Bitmap.Config.ARGB_8888, true)
        val width = mutableBitmap.width
        val height = mutableBitmap.height
        var byteIndex = 0
        var bitIndex = 0
        val totalBitsToEmbed = fullData.size * 8
        var embeddedBits = 0

        pixelLoop@ for (y in 0 until height) {
            for (x in 0 until width) {
                if (embeddedBits >= totalBitsToEmbed) break@pixelLoop
                val pixel = mutableBitmap.getPixel(x, y)
                val alpha = Color.alpha(pixel)
                var red = Color.red(pixel)
                var green = Color.green(pixel)
                var blue = Color.blue(pixel)

                if (embeddedBits < totalBitsToEmbed) {
                    val bit = (fullData[byteIndex].toInt() ushr (7 - bitIndex)) and 0x01
                    red = (red and 0xFE) or bit
                    embeddedBits++
                    bitIndex++
                    if (bitIndex == 8) {
                        bitIndex = 0
                        byteIndex++
                    }
                }

                if (embeddedBits < totalBitsToEmbed) {
                    val bit = (fullData[byteIndex].toInt() ushr (7 - bitIndex)) and 0x01
                    green = (green and 0xFE) or bit
                    embeddedBits++
                    bitIndex++
                    if (bitIndex == 8) {
                        bitIndex = 0
                        byteIndex++
                    }
                }

                if (embeddedBits < totalBitsToEmbed) {
                    val bit = (fullData[byteIndex].toInt() ushr (7 - bitIndex)) and 0x01
                    blue = (blue and 0xFE) or bit
                    embeddedBits++
                    bitIndex++
                    if (bitIndex == 8) {
                        bitIndex = 0
                        byteIndex++
                    }
                }

                mutableBitmap.setPixel(x, y, Color.argb(alpha, red, green, blue))
            }
        }
        return mutableBitmap
    }

    fun extractPayload(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        var currentByte = 0
        var bitCount = 0
        val extractedBytes = mutableListOf<Byte>()
        var targetTotalBytes = -1

        pixelLoop@ for (y in 0 until height) {
            for (x in 0 until width) {
                val pixel = bitmap.getPixel(x, y)
                val channels = intArrayOf(Color.red(pixel), Color.green(pixel), Color.blue(pixel))
                for (channel in channels) {
                    val lsb = channel and 0x01
                    currentByte = (currentByte shl 1) or lsb
                    bitCount++
                    if (bitCount == 8) {
                        extractedBytes.add(currentByte.toByte())
                        currentByte = 0
                        bitCount = 0

                        if (extractedBytes.size == MAGIC_HEADER.size) {
                            for (i in 0 until MAGIC_HEADER.size) {
                                if (extractedBytes[i] != MAGIC_HEADER[i]) {
                                    return null
                                }
                            }
                        }

                        if (extractedBytes.size == MAGIC_HEADER.size + 4 && targetTotalBytes == -1) {
                            val lenBuffer = ByteBuffer.wrap(
                                byteArrayOf(
                                    extractedBytes[4],
                                    extractedBytes[5],
                                    extractedBytes[6],
                                    extractedBytes[7]
                                )
                            ).order(ByteOrder.BIG_ENDIAN)
                            val payloadLen = lenBuffer.int
                            if (payloadLen <= 0 || payloadLen > calculateCapacity(width, height)) {
                                return null
                            }
                            targetTotalBytes = MAGIC_HEADER.size + 4 + payloadLen
                        }
                        if (targetTotalBytes != -1 && extractedBytes.size >= targetTotalBytes) {
                            break@pixelLoop
                        }
                    }
                }
            }
        }
        if (targetTotalBytes != -1 && extractedBytes.size >= targetTotalBytes) {
            val payloadBytes = extractedBytes.subList(8, targetTotalBytes).toByteArray()
            return String(payloadBytes, Charsets.UTF_8)
        }
        return null
    }
}
