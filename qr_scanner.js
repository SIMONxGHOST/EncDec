/**
 * EncDec Studio Pro — Advanced QR Code Scanner & Decoder Module
 * ==========================================================================
 * Fully self-contained, client-side QR code scanner with zero dependencies.
 * Features:
 * - Live Camera Scanner with continuous requestAnimationFrame video loop.
 * - Image file upload, Drag & Drop, and Clipboard Paste decoding.
 * - Hardware-accelerated BarcodeDetector API fast-path (when supported).
 * - High-precision pure JavaScript QR Code detection & Reed-Solomon engine.
 * - Multi-scale & adaptive binarization fallback for low-contrast/noisy images.
 * - Backend /api/scan-qr fallback support for server environments.
 */

(function(root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.QRScanner = factory();
    }
}(typeof self !== 'undefined' ? self : this, function() {
    'use strict';

    // =========================================================================
    // 1. Pure JavaScript QR Code Decoder Engine (Reed-Solomon & Geometry)
    // =========================================================================

    const EXP_TABLE = new Uint8Array(512);
    const LOG_TABLE = new Uint8Array(256);
    let x = 1;
    for (let i = 0; i < 255; i++) {
        EXP_TABLE[i] = x;
        EXP_TABLE[i + 255] = x;
        LOG_TABLE[x] = i;
        x = (x << 1) ^ (x & 0x80 ? 0x11D : 0);
    }
    LOG_TABLE[0] = 0;

    function gfMul(a, b) {
        if (a === 0 || b === 0) return 0;
        return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
    }

    function gfDiv(a, b) {
        if (b === 0) throw new Error("GF(256) division by zero");
        if (a === 0) return 0;
        let diff = LOG_TABLE[a] - LOG_TABLE[b];
        if (diff < 0) diff += 255;
        return EXP_TABLE[diff];
    }

    function gfPolyMul(p1, p2) {
        if (p1.length === 0 || p2.length === 0) return new Uint8Array(0);
        const res = new Uint8Array(p1.length + p2.length - 1);
        for (let i = 0; i < p1.length; i++) {
            for (let j = 0; j < p2.length; j++) {
                res[i + j] ^= gfMul(p1[i], p2[j]);
            }
        }
        return res;
    }

    function gfPolyEval(p, xVal) {
        let res = 0;
        for (let i = 0; i < p.length; i++) {
            res = gfMul(res, xVal) ^ p[i];
        }
        return res;
    }

    function correctErrors(received, numEccCodewords) {
        const syndromes = new Uint8Array(numEccCodewords);
        let hasError = false;
        for (let i = 0; i < numEccCodewords; i++) {
            const syn = gfPolyEval(received, EXP_TABLE[i]);
            syndromes[numEccCodewords - 1 - i] = syn;
            if (syn !== 0) hasError = true;
        }

        if (!hasError) {
            return received.slice(0, received.length - numEccCodewords);
        }

        let rLast = new Uint8Array(numEccCodewords + 1);
        rLast[0] = 1;
        let r = new Uint8Array(syndromes);
        let rStart = 0;
        while (rStart < r.length && r[rStart] === 0) rStart++;
        r = r.slice(rStart);

        let tLast = new Uint8Array([0]);
        let t = new Uint8Array([1]);

        while (r.length >= Math.floor(numEccCodewords / 2) + 1) {
            let rLastLast = rLast;
            let tLastLast = tLast;
            rLast = r;
            tLast = t;

            if (rLast.length === 0 || rLast[0] === 0) {
                throw new Error("Reed-Solomon decoding failed: rLast is zero");
            }

            r = rLastLast;
            let q = new Uint8Array([0]);
            const dltInverse = gfDiv(1, rLast[0]);

            while (r.length >= rLast.length && r.length > 0 && r[0] !== 0) {
                const degreeDiff = r.length - rLast.length;
                const scale = gfMul(r[0], dltInverse);
                const term = new Uint8Array(degreeDiff + 1);
                term[0] = scale;

                const newQ = new Uint8Array(Math.max(q.length, term.length));
                for (let i = 0; i < q.length; i++) newQ[newQ.length - q.length + i] ^= q[i];
                for (let i = 0; i < term.length; i++) newQ[newQ.length - term.length + i] ^= term[i];
                q = newQ;

                const sub = gfPolyMul(term, rLast);
                const newR = new Uint8Array(Math.max(r.length, sub.length));
                for (let i = 0; i < r.length; i++) newR[newR.length - r.length + i] ^= r[i];
                for (let i = 0; i < sub.length; i++) newR[newR.length - sub.length + i] ^= sub[i];
                let start = 0;
                while (start < newR.length && newR[start] === 0) start++;
                r = newR.slice(start);
            }

            const qTimesTLast = gfPolyMul(q, tLast);
            const newT = new Uint8Array(Math.max(tLastLast.length, qTimesTLast.length));
            for (let i = 0; i < tLastLast.length; i++) newT[newT.length - tLastLast.length + i] ^= tLastLast[i];
            for (let i = 0; i < qTimesTLast.length; i++) newT[newT.length - qTimesTLast.length + i] ^= qTimesTLast[i];
            let tStart = 0;
            while (tStart < newT.length && newT[tStart] === 0) tStart++;
            t = newT.slice(tStart);
        }

        const sigmaTildeAtZero = t[t.length - 1];
        if (sigmaTildeAtZero === 0) {
            throw new Error("Reed-Solomon decoding failed: sigmaTilde(0) = 0");
        }

        const inverse = gfDiv(1, sigmaTildeAtZero);
        const sigma = new Uint8Array(t.length);
        for (let i = 0; i < t.length; i++) sigma[i] = gfMul(t[i], inverse);
        const omega = new Uint8Array(r.length);
        for (let i = 0; i < r.length; i++) omega[i] = gfMul(r[i], inverse);

        const numErrors = sigma.length - 1;
        const errorLocations = [];
        for (let i = 1; i < 256; i++) {
            if (gfPolyEval(sigma, i) === 0) {
                errorLocations.push(gfDiv(1, i));
            }
        }

        if (errorLocations.length !== numErrors) {
            throw new Error("Reed-Solomon decoding error count mismatch");
        }

        const result = new Uint8Array(received);
        for (let i = 0; i < errorLocations.length; i++) {
            const xi = errorLocations[i];
            const xiInverse = gfDiv(1, xi);

            let denominator = 1;
            for (let j = 0; j < errorLocations.length; j++) {
                if (i !== j) {
                    denominator = gfMul(denominator, 1 ^ gfMul(errorLocations[j], xiInverse));
                }
            }

            const numerator = gfPolyEval(omega, xiInverse);
            const magnitude = gfDiv(numerator, denominator);
            const position = received.length - 1 - LOG_TABLE[xi];
            if (position < 0 || position >= received.length) {
                throw new Error("Invalid error position in Reed-Solomon decode");
            }
            result[position] ^= magnitude;
        }

        return result.slice(0, received.length - numEccCodewords);
    }

    const EC_TABLE = {
        1: [ [26, 7, 1, 19, 0, 0], [26, 10, 1, 16, 0, 0], [26, 13, 1, 13, 0, 0], [26, 17, 1, 9, 0, 0] ],
        2: [ [44, 10, 1, 34, 0, 0], [44, 16, 1, 28, 0, 0], [44, 22, 1, 22, 0, 0], [44, 28, 1, 16, 0, 0] ],
        3: [ [70, 15, 1, 55, 0, 0], [70, 26, 1, 44, 0, 0], [70, 18, 2, 17, 0, 0], [70, 22, 2, 13, 0, 0] ],
        4: [ [100, 20, 1, 80, 0, 0], [100, 18, 2, 32, 0, 0], [100, 26, 2, 24, 0, 0], [100, 16, 4, 9, 0, 0] ],
        5: [ [134, 26, 1, 108, 0, 0], [134, 24, 2, 43, 0, 0], [134, 18, 2, 15, 2, 16], [134, 22, 2, 11, 2, 12] ],
        6: [ [172, 18, 2, 68, 0, 0], [172, 16, 4, 27, 0, 0], [172, 24, 4, 19, 0, 0], [172, 28, 4, 15, 0, 0] ],
        7: [ [196, 20, 2, 78, 0, 0], [196, 18, 4, 31, 0, 0], [196, 18, 2, 14, 4, 15], [196, 26, 4, 13, 1, 14] ],
        8: [ [242, 24, 2, 97, 0, 0], [242, 22, 2, 38, 2, 39], [242, 22, 4, 18, 2, 19], [242, 26, 4, 14, 2, 15] ],
        9: [ [292, 30, 2, 116, 0, 0], [292, 22, 3, 36, 2, 37], [292, 20, 4, 16, 4, 17], [292, 24, 4, 12, 4, 13] ],
        10: [ [346, 18, 2, 68, 2, 69], [346, 26, 4, 43, 1, 44], [346, 24, 6, 19, 2, 20], [346, 28, 6, 15, 2, 16] ],
        11: [ [404, 20, 4, 81, 0, 0], [404, 30, 1, 50, 4, 51], [404, 28, 4, 22, 4, 23], [404, 24, 3, 12, 8, 13] ],
        12: [ [466, 24, 2, 92, 2, 93], [466, 22, 6, 36, 2, 37], [466, 26, 4, 20, 6, 21], [466, 28, 7, 14, 4, 15] ],
        13: [ [532, 26, 4, 107, 0, 0], [532, 22, 8, 37, 1, 38], [532, 24, 8, 20, 4, 21], [532, 22, 12, 11, 4, 12] ],
        14: [ [581, 30, 3, 115, 1, 116], [581, 24, 4, 40, 5, 41], [581, 20, 11, 16, 5, 17], [581, 24, 11, 12, 5, 13] ],
        15: [ [655, 22, 5, 87, 1, 88], [655, 24, 5, 41, 5, 42], [655, 30, 5, 24, 7, 25], [655, 24, 11, 12, 7, 13] ],
        16: [ [733, 24, 5, 98, 1, 99], [733, 28, 7, 45, 3, 46], [733, 24, 15, 19, 2, 20], [733, 30, 3, 15, 13, 16] ],
        17: [ [815, 28, 1, 107, 5, 108], [815, 28, 10, 46, 1, 47], [815, 28, 1, 22, 15, 23], [815, 28, 2, 14, 17, 15] ],
        18: [ [901, 30, 5, 120, 1, 121], [901, 26, 9, 43, 4, 44], [901, 28, 17, 22, 1, 23], [901, 28, 2, 14, 19, 15] ],
        19: [ [991, 28, 3, 113, 4, 114], [991, 26, 3, 44, 11, 45], [991, 26, 17, 21, 4, 22], [991, 26, 9, 13, 16, 14] ],
        20: [ [1085, 28, 3, 107, 5, 108], [1085, 26, 3, 41, 13, 42], [1085, 30, 15, 24, 5, 25], [1085, 28, 15, 15, 10, 16] ],
        21: [ [1156, 28, 4, 116, 4, 117], [1156, 26, 17, 42, 0, 0], [1156, 28, 17, 22, 6, 23], [1156, 30, 19, 16, 6, 17] ],
        22: [ [1258, 28, 2, 111, 7, 112], [1258, 28, 17, 46, 0, 0], [1258, 30, 7, 24, 16, 25], [1258, 24, 34, 13, 0, 0] ],
        23: [ [1364, 30, 4, 121, 5, 122], [1364, 28, 4, 47, 14, 48], [1364, 30, 11, 24, 14, 25], [1364, 30, 16, 15, 14, 16] ],
        24: [ [1474, 30, 6, 117, 4, 118], [1474, 28, 6, 45, 14, 46], [1474, 30, 11, 24, 16, 25], [1474, 30, 30, 16, 2, 17] ],
        25: [ [1588, 26, 8, 106, 4, 107], [1588, 28, 8, 47, 13, 48], [1588, 30, 7, 24, 22, 25], [1588, 30, 22, 15, 13, 16] ],
        26: [ [1706, 28, 10, 114, 2, 115], [1706, 28, 19, 46, 4, 47], [1706, 28, 28, 22, 6, 23], [1706, 30, 33, 16, 4, 17] ],
        27: [ [1828, 30, 8, 122, 4, 123], [1828, 28, 22, 45, 3, 46], [1828, 30, 8, 23, 26, 24], [1828, 30, 12, 15, 28, 16] ],
        28: [ [1921, 30, 3, 117, 10, 118], [1921, 28, 3, 45, 23, 46], [1921, 30, 4, 24, 31, 25], [1921, 30, 11, 15, 31, 16] ],
        29: [ [2051, 30, 7, 116, 7, 117], [2051, 28, 21, 45, 7, 46], [2051, 30, 1, 23, 37, 24], [2051, 30, 19, 15, 26, 16] ],
        30: [ [2185, 30, 5, 115, 10, 116], [2185, 28, 19, 47, 10, 48], [2185, 30, 15, 24, 25, 25], [2185, 30, 23, 15, 25, 16] ],
        31: [ [2323, 30, 13, 115, 3, 116], [2323, 28, 2, 46, 29, 47], [2323, 30, 42, 24, 1, 25], [2323, 30, 23, 15, 28, 16] ],
        32: [ [2465, 30, 17, 115, 0, 0], [2465, 28, 10, 46, 23, 47], [2465, 30, 10, 24, 35, 25], [2465, 30, 19, 15, 35, 16] ],
        33: [ [2611, 30, 17, 115, 1, 116], [2611, 28, 14, 46, 21, 47], [2611, 30, 29, 24, 19, 25], [2611, 30, 11, 15, 46, 16] ],
        34: [ [2761, 30, 13, 115, 6, 116], [2761, 28, 14, 46, 23, 47], [2761, 30, 44, 24, 7, 25], [2761, 30, 59, 16, 1, 17] ],
        35: [ [2876, 30, 12, 121, 7, 122], [2876, 28, 12, 47, 26, 48], [2876, 30, 39, 24, 14, 25], [2876, 30, 22, 15, 41, 16] ],
        36: [ [3034, 30, 6, 121, 14, 122], [3034, 28, 6, 47, 34, 48], [3034, 30, 46, 24, 10, 25], [3034, 30, 2, 15, 64, 16] ],
        37: [ [3196, 30, 17, 122, 4, 123], [3196, 28, 29, 46, 14, 47], [3196, 30, 49, 24, 10, 25], [3196, 30, 24, 15, 46, 16] ],
        38: [ [3362, 30, 4, 122, 18, 123], [3362, 28, 13, 46, 32, 47], [3362, 30, 48, 24, 14, 25], [3362, 30, 42, 15, 32, 16] ],
        39: [ [3532, 30, 20, 117, 4, 118], [3532, 28, 40, 47, 7, 48], [3532, 30, 43, 24, 22, 25], [3532, 30, 10, 15, 67, 16] ],
        40: [ [3706, 30, 19, 118, 6, 119], [3706, 28, 18, 47, 31, 48], [3706, 30, 34, 24, 34, 25], [3706, 30, 20, 15, 61, 16] ]
    };

    const ALIGNMENT_PATTERN_LOCATIONS = {
        1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
        7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
        11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
        15: [6, 26, 48, 70], 16: [6, 26, 50, 74], 17: [6, 30, 54, 78],
        18: [6, 30, 56, 82], 19: [6, 30, 58, 86], 20: [6, 34, 62, 90],
        21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98], 23: [6, 30, 54, 78, 102],
        24: [6, 28, 54, 80, 106], 25: [6, 32, 58, 84, 110], 26: [6, 30, 58, 86, 114],
        27: [6, 34, 62, 90, 118], 28: [6, 26, 50, 74, 98, 122], 29: [6, 30, 54, 78, 102, 126],
        30: [6, 26, 52, 78, 104, 130], 31: [6, 30, 56, 82, 108, 134],
        32: [6, 34, 60, 86, 112, 138], 33: [6, 30, 58, 86, 114, 142],
        34: [6, 34, 62, 90, 118, 146], 35: [6, 30, 54, 78, 102, 126, 150],
        36: [6, 24, 50, 76, 102, 128, 154], 37: [6, 28, 54, 80, 106, 132, 158],
        38: [6, 32, 58, 84, 110, 136, 162], 39: [6, 26, 54, 82, 110, 138, 166],
        40: [6, 30, 58, 86, 114, 142, 170]
    };

    const FORMAT_INFO_TABLE = [
        0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
        0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976,
        0x1689, 0x13BE, 0x1CE7, 0x19D0, 0x0763, 0x0254, 0x0D0D, 0x083A,
        0x359F, 0x30A8, 0x3FD1, 0x3AFA, 0x2474, 0x2143, 0x2E1A, 0x2B2D
    ];

    function countBits(n) {
        let count = 0;
        while (n > 0) {
            count += n & 1;
            n >>>= 1;
        }
        return count;
    }

    function decodeFormatInfo(format1, format2) {
        let bestInfo = -1;
        let bestDiff = Infinity;

        for (let target = 0; target < 32; target++) {
            const pattern = FORMAT_INFO_TABLE[target];
            if (format1 !== undefined) {
                const diff1 = countBits((format1 ^ pattern) & 0x7FFF);
                if (diff1 < bestDiff) {
                    bestInfo = target;
                    bestDiff = diff1;
                }
            }
            if (format2 !== undefined) {
                const diff2 = countBits((format2 ^ pattern) & 0x7FFF);
                if (diff2 < bestDiff) {
                    bestInfo = target;
                    bestDiff = diff2;
                }
            }
        }

        if (bestDiff <= 3) {
            return {
                ecLevel: (bestInfo >> 3) & 0x03,
                maskPattern: bestInfo & 0x07
            };
        }
        return null;
    }

    function isMasked(maskIndex, row, col) {
        switch (maskIndex) {
            case 0: return ((row + col) & 1) === 0;
            case 1: return (row & 1) === 0;
            case 2: return col % 3 === 0;
            case 3: return (row + col) % 3 === 0;
            case 4: return ((Math.floor(row / 2) + Math.floor(col / 3)) & 1) === 0;
            case 5: return ((row * col) & 1) + ((row * col) % 3) === 0;
            case 6: return (((row * col) & 1) + ((row * col) % 3) & 1) === 0;
            case 7: return (((row + col) & 1) + ((row * col) % 3) & 1) === 0;
            default: return false;
        }
    }

    function isFunctionPattern(version, row, col) {
        const size = version * 4 + 17;
        if (row <= 8 && col <= 8) return true;
        if (row <= 8 && col >= size - 8) return true;
        if (row >= size - 8 && col <= 8) return true;
        if (row === 6 || col === 6) return true;
        if (row === 4 * version + 9 && col === 8) return true;

        const alignCoords = ALIGNMENT_PATTERN_LOCATIONS[version] || [];
        for (let r of alignCoords) {
            for (let c of alignCoords) {
                if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 8) || (r >= size - 8 && c <= 8)) continue;
                if (Math.abs(row - r) <= 2 && Math.abs(col - c) <= 2) return true;
            }
        }

        if (version >= 7) {
            if (row <= 5 && col >= size - 11 && col <= size - 8) return true;
            if (col <= 5 && row >= size - 11 && row <= size - 8) return true;
        }

        return false;
    }

    function decodeBitMatrix(matrix) {
        const size = matrix.length;
        const version = (size - 17) / 4;
        if (version < 1 || version > 40 || !Number.isInteger(version)) {
            throw new Error(`Invalid QR version for matrix size ${size}`);
        }

        let format1 = 0;
        for (let c = 0; c <= 5; c++) format1 = (format1 << 1) | (matrix[8][c] ? 1 : 0);
        format1 = (format1 << 1) | (matrix[8][7] ? 1 : 0);
        format1 = (format1 << 1) | (matrix[8][8] ? 1 : 0);
        format1 = (format1 << 1) | (matrix[7][8] ? 1 : 0);
        for (let r = 5; r >= 0; r--) format1 = (format1 << 1) | (matrix[r][8] ? 1 : 0);

        let format2 = 0;
        for (let r = size - 1; r >= size - 7; r--) format2 = (format2 << 1) | (matrix[r][8] ? 1 : 0);
        for (let c = size - 8; c < size; c++) format2 = (format2 << 1) | (matrix[8][c] ? 1 : 0);

        const formatInfo = decodeFormatInfo(format1, format2);
        if (!formatInfo) {
            throw new Error("Failed to decode format information");
        }

        const ecLevelIndexMap = { 1: 0, 0: 1, 3: 2, 2: 3 };
        const ecIndex = ecLevelIndexMap[formatInfo.ecLevel];
        const ecConfig = EC_TABLE[version][ecIndex];
        const [totalCodewords, ecCodewordsPerBlock, numBlocks1, dataBytes1, numBlocks2, dataBytes2] = ecConfig;

        const unmasked = [];
        for (let r = 0; r < size; r++) {
            unmasked[r] = new Uint8Array(size);
            for (let c = 0; c < size; c++) {
                let bit = matrix[r][c] ? 1 : 0;
                if (!isFunctionPattern(version, r, c) && isMasked(formatInfo.maskPattern, r, c)) {
                    bit ^= 1;
                }
                unmasked[r][c] = bit;
            }
        }

        const allCodewords = new Uint8Array(totalCodewords);
        let bitIndex = 0;
        let byteVal = 0;
        let cwIndex = 0;

        let right = size - 1;
        let upward = true;

        while (right > 0) {
            if (right === 6) right--;

            for (let i = 0; i < size; i++) {
                const r = upward ? (size - 1 - i) : i;
                for (let cOffset = 0; cOffset < 2; cOffset++) {
                    const c = right - cOffset;
                    if (!isFunctionPattern(version, r, c)) {
                        byteVal = (byteVal << 1) | unmasked[r][c];
                        bitIndex++;
                        if (bitIndex === 8) {
                            if (cwIndex < totalCodewords) {
                                allCodewords[cwIndex++] = byteVal;
                            }
                            bitIndex = 0;
                            byteVal = 0;
                        }
                    }
                }
            }
            upward = !upward;
            right -= 2;
        }

        const totalBlocks = numBlocks1 + numBlocks2;
        const blocks = [];
        for (let i = 0; i < totalBlocks; i++) {
            const dataLen = i < numBlocks1 ? dataBytes1 : dataBytes2;
            blocks[i] = new Uint8Array(dataLen + ecCodewordsPerBlock);
        }

        let offset = 0;
        const maxDataBytes = Math.max(dataBytes1, dataBytes2);
        for (let d = 0; d < maxDataBytes; d++) {
            for (let b = 0; b < totalBlocks; b++) {
                const dataLen = b < numBlocks1 ? dataBytes1 : dataBytes2;
                if (d < dataLen && offset < allCodewords.length) {
                    blocks[b][d] = allCodewords[offset++];
                }
            }
        }

        for (let ec = 0; ec < ecCodewordsPerBlock; ec++) {
            for (let b = 0; b < totalBlocks; b++) {
                const dataLen = b < numBlocks1 ? dataBytes1 : dataBytes2;
                if (offset < allCodewords.length) {
                    blocks[b][dataLen + ec] = allCodewords[offset++];
                }
            }
        }

        const correctedData = [];
        for (let b = 0; b < totalBlocks; b++) {
            const corrected = correctErrors(blocks[b], ecCodewordsPerBlock);
            for (let byte of corrected) correctedData.push(byte);
        }

        return parsePayload(new Uint8Array(correctedData), version);
    }

    function parsePayload(dataBytes, version) {
        let bitOffset = 0;
        function readBits(numBits) {
            let res = 0;
            for (let i = 0; i < numBits; i++) {
                const byteIdx = Math.floor(bitOffset / 8);
                const bitIdx = 7 - (bitOffset % 8);
                bitOffset++;
                if (byteIdx < dataBytes.length) {
                    const bit = (dataBytes[byteIdx] >> bitIdx) & 1;
                    res = (res << 1) | bit;
                }
            }
            return res;
        }

        let resultBytes = [];
        const ALPHANUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

        while (bitOffset + 4 <= dataBytes.length * 8) {
            const mode = readBits(4);
            if (mode === 0x00) break;

            if (mode === 0x01) { // Numeric
                const countBits = version <= 9 ? 10 : (version <= 26 ? 12 : 14);
                let count = readBits(countBits);
                while (count >= 3) {
                    const val = readBits(10);
                    const s = val.toString().padStart(3, '0');
                    for (let ch of s) resultBytes.push(ch.charCodeAt(0));
                    count -= 3;
                }
                if (count === 2) {
                    const val = readBits(7);
                    const s = val.toString().padStart(2, '0');
                    for (let ch of s) resultBytes.push(ch.charCodeAt(0));
                } else if (count === 1) {
                    const val = readBits(4);
                    resultBytes.push(val.toString().charCodeAt(0));
                }
            } else if (mode === 0x02) { // Alphanumeric
                const countBits = version <= 9 ? 9 : (version <= 26 ? 11 : 13);
                let count = readBits(countBits);
                while (count >= 2) {
                    const val = readBits(11);
                    const c1 = Math.floor(val / 45);
                    const c2 = val % 45;
                    resultBytes.push(ALPHANUMERIC_CHARS.charCodeAt(c1));
                    resultBytes.push(ALPHANUMERIC_CHARS.charCodeAt(c2));
                    count -= 2;
                }
                if (count === 1) {
                    const val = readBits(6);
                    resultBytes.push(ALPHANUMERIC_CHARS.charCodeAt(val));
                }
            } else if (mode === 0x04) { // Byte mode
                const countBits = version <= 9 ? 8 : 16;
                const count = readBits(countBits);
                for (let i = 0; i < count; i++) {
                    resultBytes.push(readBits(8));
                }
            } else if (mode === 0x07) { // ECI
                let eciVal = readBits(8);
                if ((eciVal & 0xC0) === 0x80) eciVal = ((eciVal & 0x3F) << 8) | readBits(8);
                else if ((eciVal & 0xE0) === 0xC0) eciVal = ((eciVal & 0x1F) << 16) | readBits(16);
            } else if (mode === 0x03) { // Structured Append
                readBits(16);
            } else {
                break;
            }
        }

        return new TextDecoder('utf-8').decode(new Uint8Array(resultBytes));
    }

    function binarizeImage(rgbaData, width, height) {
        const gray = new Uint8Array(width * height);
        for (let i = 0; i < width * height; i++) {
            const idx = i * 4;
            gray[i] = (rgbaData[idx] * 77 + rgbaData[idx + 1] * 150 + rgbaData[idx + 2] * 29) >> 8;
        }

        const binarized = new Uint8Array(width * height);
        const BLOCK_SIZE = 16;
        const numBlocksX = Math.ceil(width / BLOCK_SIZE);
        const numBlocksY = Math.ceil(height / BLOCK_SIZE);
        const blockMins = new Uint8Array(numBlocksX * numBlocksY);
        const blockMaxs = new Uint8Array(numBlocksX * numBlocksY);

        for (let by = 0; by < numBlocksY; by++) {
            for (let bx = 0; bx < numBlocksX; bx++) {
                let min = 255, max = 0;
                const startY = by * BLOCK_SIZE;
                const endY = Math.min(startY + BLOCK_SIZE, height);
                const startX = bx * BLOCK_SIZE;
                const endX = Math.min(startX + BLOCK_SIZE, width);

                for (let y = startY; y < endY; y++) {
                    const rowOffset = y * width;
                    for (let x = startX; x < endX; x++) {
                        const val = gray[rowOffset + x];
                        if (val < min) min = val;
                        if (val > max) max = val;
                    }
                }
                blockMins[by * numBlocksX + bx] = min;
                blockMaxs[by * numBlocksX + bx] = max;
            }
        }

        for (let by = 0; by < numBlocksY; by++) {
            for (let bx = 0; bx < numBlocksX; bx++) {
                let sum = 0, count = 0;
                let minNeighbor = 255, maxNeighbor = 0;

                for (let dy = -1; dy <= 1; dy++) {
                    const ny = by + dy;
                    if (ny < 0 || ny >= numBlocksY) continue;
                    for (let dx = -1; dx <= 1; dx++) {
                        const nx = bx + dx;
                        if (nx < 0 || nx >= numBlocksX) continue;
                        const bIdx = ny * numBlocksX + nx;
                        const bMin = blockMins[bIdx];
                        const bMax = blockMaxs[bIdx];
                        sum += (bMin + bMax) >> 1;
                        count++;
                        if (bMin < minNeighbor) minNeighbor = bMin;
                        if (bMax > maxNeighbor) maxNeighbor = bMax;
                    }
                }

                let threshold = Math.floor(sum / count);
                if (maxNeighbor - minNeighbor <= 24) {
                    threshold = minNeighbor >> 1;
                }

                const startY = by * BLOCK_SIZE;
                const endY = Math.min(startY + BLOCK_SIZE, height);
                const startX = bx * BLOCK_SIZE;
                const endX = Math.min(startX + BLOCK_SIZE, width);

                for (let y = startY; y < endY; y++) {
                    const rowOffset = y * width;
                    for (let x = startX; x < endX; x++) {
                        binarized[rowOffset + x] = gray[rowOffset + x] <= threshold ? 1 : 0;
                    }
                }
            }
        }

        return { binarized, width, height };
    }

    function checkRatio(s) {
        const total = s[0] + s[1] + s[2] + s[3] + s[4];
        if (total < 7) return false;
        const m = total / 7.0;
        const maxVar = m * 0.55;
        return Math.abs(m - s[0]) < maxVar &&
               Math.abs(m - s[1]) < maxVar &&
               Math.abs(3.0 * m - s[2]) < 3.0 * maxVar &&
               Math.abs(m - s[3]) < maxVar &&
               Math.abs(m - s[4]) < maxVar;
    }

    function crossCheckVertical(binarized, width, height, startY, centerCol, maxCount, originalTotal) {
        const s = [0, 0, 0, 0, 0];
        let y = startY;
        const c = Math.floor(centerCol);
        if (c < 0 || c >= width) return NaN;

        while (y >= 0 && binarized[y * width + c] === 1) { s[2]++; y--; }
        if (y < 0) return NaN;
        while (y >= 0 && binarized[y * width + c] === 0 && s[1] <= maxCount) { s[1]++; y--; }
        if (y < 0 || s[1] > maxCount) return NaN;
        while (y >= 0 && binarized[y * width + c] === 1 && s[0] <= maxCount) { s[0]++; y--; }
        if (y < 0 || s[0] > maxCount) return NaN;

        y = startY + 1;
        while (y < height && binarized[y * width + c] === 1) { s[2]++; y++; }
        if (y >= height) return NaN;
        while (y < height && binarized[y * width + c] === 0 && s[3] <= maxCount) { s[3]++; y++; }
        if (y >= height || s[3] > maxCount) return NaN;
        while (y < height && binarized[y * width + c] === 1 && s[4] <= maxCount) { s[4]++; y++; }
        if (y >= height || s[4] > maxCount) return NaN;

        const total = s[0] + s[1] + s[2] + s[3] + s[4];
        if (Math.abs(total - originalTotal) * 5 >= 2 * originalTotal) return NaN;

        return checkRatio(s) ? (y - s[4] - s[3] - s[2] / 2.0) : NaN;
    }

    function crossCheckHorizontal(binarized, width, height, startX, centerRow, maxCount, originalTotal) {
        const s = [0, 0, 0, 0, 0];
        let x = startX;
        const r = Math.floor(centerRow);
        if (r < 0 || r >= height) return NaN;
        const rowOffset = r * width;

        while (x >= 0 && binarized[rowOffset + x] === 1) { s[2]++; x--; }
        if (x < 0) return NaN;
        while (x >= 0 && binarized[rowOffset + x] === 0 && s[1] <= maxCount) { s[1]++; x--; }
        if (x < 0 || s[1] > maxCount) return NaN;
        while (x >= 0 && binarized[rowOffset + x] === 1 && s[0] <= maxCount) { s[0]++; x--; }
        if (x < 0 || s[0] > maxCount) return NaN;

        x = startX + 1;
        while (x < width && binarized[rowOffset + x] === 1) { s[2]++; x++; }
        if (x >= width) return NaN;
        while (x < width && binarized[rowOffset + x] === 0 && s[3] <= maxCount) { s[3]++; x++; }
        if (x >= width || s[3] > maxCount) return NaN;
        while (x < width && binarized[rowOffset + x] === 1 && s[4] <= maxCount) { s[4]++; x++; }
        if (x >= width || s[4] > maxCount) return NaN;

        const total = s[0] + s[1] + s[2] + s[3] + s[4];
        if (Math.abs(total - originalTotal) * 5 >= 2 * originalTotal) return NaN;

        return checkRatio(s) ? (x - s[4] - s[3] - s[2] / 2.0) : NaN;
    }

    function findFinderPatterns(binarized, width, height) {
        const patterns = [];
        for (let y = 0; y < height; y += 2) {
            const state = [0, 0, 0, 0, 0];
            let currentColor = 0;
            let currentRun = 0;
            const rowOffset = y * width;

            for (let x = 0; x < width; x++) {
                const p = binarized[rowOffset + x];
                if (p === currentColor) {
                    currentRun++;
                } else {
                    state[0] = state[1]; state[1] = state[2]; state[2] = state[3]; state[3] = state[4]; state[4] = currentRun;
                    if (currentColor === 1 && checkRatio(state)) {
                        const total = state[0] + state[1] + state[2] + state[3] + state[4];
                        const cx = x - state[4] - state[3] - state[2] / 2.0;
                        const cy = crossCheckVertical(binarized, width, height, y, cx, state[2], total);
                        if (!isNaN(cy)) {
                            const exactX = crossCheckHorizontal(binarized, width, height, Math.floor(cx), cy, state[2], total);
                            if (!isNaN(exactX)) {
                                const modSize = total / 7.0;
                                let found = false;
                                for (let pt of patterns) {
                                    if (Math.hypot(pt.x - exactX, pt.y - cy) < modSize * 1.5) {
                                        pt.x = (pt.x + exactX) / 2;
                                        pt.y = (pt.y + cy) / 2;
                                        pt.count++;
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    patterns.push({ x: exactX, y: cy, moduleSize: modSize, count: 1 });
                                }
                            }
                        }
                    }
                    currentColor = p;
                    currentRun = 1;
                }
            }
        }
        return patterns;
    }

    function distance(p1, p2) {
        return Math.hypot(p1.x - p2.x, p1.y - p2.y);
    }

    function orderFinderPatterns(patterns) {
        if (patterns.length < 3) return null;

        const sorted = patterns.slice().sort((a, b) => b.count - a.count);
        const candidates = sorted.slice(0, Math.min(sorted.length, 10));

        let bestTri = null;
        let bestScore = Infinity;

        for (let i = 0; i < candidates.length; i++) {
            for (let j = i + 1; j < candidates.length; j++) {
                for (let k = j + 1; k < candidates.length; k++) {
                    const p1 = candidates[i], p2 = candidates[j], p3 = candidates[k];
                    const d12 = distance(p1, p2);
                    const d23 = distance(p2, p3);
                    const d13 = distance(p1, p3);

                    let tl, tr, bl;
                    if (d12 >= d23 && d12 >= d13) {
                        tl = p3; tr = p1; bl = p2;
                    } else if (d23 >= d12 && d23 >= d13) {
                        tl = p1; tr = p2; bl = p3;
                    } else {
                        tl = p2; tr = p1; bl = p3;
                    }

                    const cross = (tr.x - tl.x) * (bl.y - tl.y) - (tr.y - tl.y) * (bl.x - tl.x);
                    if (cross < 0) {
                        const tmp = tr; tr = bl; bl = tmp;
                    }

                    const distTR = distance(tl, tr);
                    const distBL = distance(tl, bl);
                    const ratio = distTR / distBL;
                    if (ratio > 0.65 && ratio < 1.35) {
                        const score = Math.abs(1.0 - ratio) + Math.abs(tl.moduleSize - tr.moduleSize) / tl.moduleSize;
                        if (score < bestScore) {
                            bestScore = score;
                            bestTri = { tl, tr, bl };
                        }
                    }
                }
            }
        }
        return bestTri;
    }

    function getPerspectiveTransform(src, dst) {
        const a = [];
        for (let i = 0; i < 4; i++) {
            a.push([src[i].x, src[i].y, 1, 0, 0, 0, -src[i].x * dst[i].x, -src[i].y * dst[i].x, dst[i].x]);
            a.push([0, 0, 0, src[i].x, src[i].y, 1, -src[i].x * dst[i].y, -src[i].y * dst[i].y, dst[i].y]);
        }

        for (let i = 0; i < 8; i++) {
            let maxRow = i;
            for (let r = i + 1; r < 8; r++) {
                if (Math.abs(a[r][i]) > Math.abs(a[maxRow][i])) maxRow = r;
            }
            const tmp = a[i]; a[i] = a[maxRow]; a[maxRow] = tmp;

            const pivot = a[i][i];
            if (Math.abs(pivot) < 1e-10) return null;
            for (let c = i; c < 9; c++) a[i][c] /= pivot;

            for (let r = 0; r < 8; r++) {
                if (r !== i) {
                    const factor = a[r][i];
                    for (let c = i; c < 9; c++) a[r][c] -= factor * a[i][c];
                }
            }
        }

        return [
            [a[0][8], a[1][8], a[2][8]],
            [a[3][8], a[4][8], a[5][8]],
            [a[6][8], a[7][8], 1]
        ];
    }

    function sampleGrid(binarized, width, height, dim, H) {
        const matrix = [];
        for (let r = 0; r < dim; r++) {
            matrix[r] = new Uint8Array(dim);
            for (let c = 0; c < dim; c++) {
                const u = c + 0.5;
                const v = r + 0.5;
                const denom = H[2][0] * u + H[2][1] * v + H[2][2];
                const x = Math.round((H[0][0] * u + H[0][1] * v + H[0][2]) / denom);
                const y = Math.round((H[1][0] * u + H[1][1] * v + H[1][2]) / denom);

                if (x >= 0 && x < width && y >= 0 && y < height) {
                    matrix[r][c] = binarized[y * width + x];
                } else {
                    matrix[r][c] = 0;
                }
            }
        }
        return matrix;
    }

    function scanImageData(imageData) {
        if (!imageData || !imageData.data || !imageData.width || !imageData.height) return null;

        const width = imageData.width;
        const height = imageData.height;
        const rgba = imageData.data;

        const { binarized } = binarizeImage(rgba, width, height);
        const patterns = findFinderPatterns(binarized, width, height);
        const finders = orderFinderPatterns(patterns);

        if (finders) {
            const { tl, tr, bl } = finders;
            const avgDist = (distance(tl, tr) + distance(tl, bl)) / 2.0;
            const avgMod = (tl.moduleSize + tr.moduleSize + bl.moduleSize) / 3.0;
            const rawDim = avgDist / avgMod + 7;
            const estV = Math.round((rawDim - 17) / 4);

            const vList = [estV, estV - 1, estV + 1, estV - 2, estV + 2].filter(v => v >= 1 && v <= 40);

            for (let v of vList) {
                const dim = v * 4 + 17;
                const br = {
                    x: tr.x + bl.x - tl.x,
                    y: tr.y + bl.y - tl.y
                };

                const srcPoints = [
                    { x: 3.5, y: 3.5 },
                    { x: dim - 3.5, y: 3.5 },
                    { x: dim - 3.5, y: dim - 3.5 },
                    { x: 3.5, y: dim - 3.5 }
                ];
                const dstPoints = [tl, tr, br, bl];

                const H = getPerspectiveTransform(srcPoints, dstPoints);
                if (H) {
                    const matrix = sampleGrid(binarized, width, height, dim, H);
                    try {
                        const text = decodeBitMatrix(matrix);
                        if (text) return { rawValue: text, format: 'qr_code' };
                    } catch (e) {}
                }
            }
        }

        // Direct crop decode fallback
        for (let v = 1; v <= 40; v++) {
            const dim = v * 4 + 17;
            if (width >= dim && height >= dim) {
                const moduleW = width / dim;
                const moduleH = height / dim;
                const matrix = [];
                for (let r = 0; r < dim; r++) {
                    matrix[r] = new Uint8Array(dim);
                    const y = Math.floor((r + 0.5) * moduleH);
                    for (let c = 0; c < dim; c++) {
                        const x = Math.floor((c + 0.5) * moduleW);
                        matrix[r][c] = binarized[y * width + x];
                    }
                }
                try {
                    const text = decodeBitMatrix(matrix);
                    if (text) return { rawValue: text, format: 'qr_code' };
                } catch (e) {}
            }
        }

        return null;
    }

    // =========================================================================
    // 2. High-Level Scanner API (Camera, Canvas, Image File, Paste)
    // =========================================================================

    let activeStream = null;
    let scanAnimationId = null;
    let barcodeDetector = null;

    if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
        try {
            barcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
        } catch (e) {
            barcodeDetector = null;
        }
    }

    /**
     * Scans an HTMLCanvasElement, ImageData, HTMLImageElement, or Video
     */
    async function scanCanvas(canvasOrImage) {
        if (!canvasOrImage) return null;

        // 1. Fast Path: Native Hardware BarcodeDetector
        if (barcodeDetector) {
            try {
                const barcodes = await barcodeDetector.detect(canvasOrImage);
                if (barcodes && barcodes.length > 0) {
                    return { rawValue: barcodes[0].rawValue, format: barcodes[0].format || 'qr_code' };
                }
            } catch (e) {
                // Fall through to pure JS decoder
            }
        }

        // 2. Pure JS Client-Side QR Decoder (Zero Dependencies)
        try {
            let imgData = null;
            let canvas = null;
            if (typeof ImageData !== 'undefined' && canvasOrImage instanceof ImageData) {
                imgData = canvasOrImage;
            } else if (typeof HTMLCanvasElement !== 'undefined' && canvasOrImage instanceof HTMLCanvasElement) {
                canvas = canvasOrImage;
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                if (ctx && canvas.width > 0 && canvas.height > 0) {
                    imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                }
            } else if (typeof document !== 'undefined' && (canvasOrImage instanceof HTMLImageElement || canvasOrImage instanceof HTMLVideoElement)) {
                canvas = document.createElement('canvas');
                const w = canvasOrImage.naturalWidth || canvasOrImage.videoWidth || canvasOrImage.width;
                const h = canvasOrImage.naturalHeight || canvasOrImage.videoHeight || canvasOrImage.height;
                if (w > 0 && h > 0) {
                    canvas.width = w;
                    canvas.height = h;
                    const ctx = canvas.getContext('2d', { willReadFrequently: true });
                    ctx.drawImage(canvasOrImage, 0, 0, w, h);
                    imgData = ctx.getImageData(0, 0, w, h);
                }
            }

            if (imgData) {
                let result = scanImageData(imgData);
                if (result && result.rawValue) {
                    return result;
                }

                // Inversion check for inverted / dark-theme QR codes
                const invertedData = new Uint8ClampedArray(imgData.data.length);
                for (let i = 0; i < imgData.data.length; i += 4) {
                    invertedData[i] = 255 - imgData.data[i];
                    invertedData[i + 1] = 255 - imgData.data[i + 1];
                    invertedData[i + 2] = 255 - imgData.data[i + 2];
                    invertedData[i + 3] = imgData.data[i + 3];
                }
                const invertedImgData = { width: imgData.width, height: imgData.height, data: invertedData };
                result = scanImageData(invertedImgData);
                if (result && result.rawValue) {
                    return result;
                }

                // Downscale large image if > 800px
                if (canvas && (canvas.width > 800 || canvas.height > 800)) {
                    const maxDim = 800;
                    const scale = Math.min(maxDim / canvas.width, maxDim / canvas.height);
                    const sw = Math.round(canvas.width * scale);
                    const sh = Math.round(canvas.height * scale);
                    const scaledCanvas = document.createElement('canvas');
                    scaledCanvas.width = sw;
                    scaledCanvas.height = sh;
                    const sctx = scaledCanvas.getContext('2d', { willReadFrequently: true });
                    sctx.drawImage(canvas, 0, 0, sw, sh);
                    const scaledImgData = sctx.getImageData(0, 0, sw, sh);
                    result = scanImageData(scaledImgData);
                    if (result && result.rawValue) {
                        return result;
                    }
                }
            }
        } catch (e) {
            // Fall through to backend fallback
        }

        // 3. Optional Server Backend API Fallback
        if (typeof fetch !== 'undefined' && typeof HTMLCanvasElement !== 'undefined' && canvasOrImage instanceof HTMLCanvasElement) {
            try {
                const dataUrl = canvasOrImage.toDataURL('image/png');
                const res = await fetch('/api/scan-qr', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ image_base64: dataUrl })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data && data.success && data.text) {
                        return { rawValue: data.text, format: 'qr_code' };
                    }
                }
            } catch (e) {}
        }

        return null;
    }

    /**
     * Start live camera stream and continuous scanning loop
     */
    async function startCamera(videoElement, onScanSuccess, onError, facingMode = 'environment') {
        stopCamera();

        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            if (onError) onError(new Error("Camera access is not supported in this browser context (requires HTTPS or localhost)."));
            return;
        }

        try {
            const constraints = {
                video: {
                    facingMode: { ideal: facingMode },
                    width: { ideal: 1280 },
                    height: { ideal: 720 }
                },
                audio: false
            };

            activeStream = await navigator.mediaDevices.getUserMedia(constraints);
            videoElement.srcObject = activeStream;
            videoElement.setAttribute('playsinline', 'true');
            await videoElement.play();

            startScanLoop(videoElement, onScanSuccess);
        } catch (err) {
            if (onError) onError(err);
        }
    }

    /**
     * Stop camera stream and cancel animation frames
     */
    function stopCamera() {
        if (scanAnimationId) {
            cancelAnimationFrame(scanAnimationId);
            scanAnimationId = null;
        }
        if (activeStream) {
            activeStream.getTracks().forEach(track => track.stop());
            activeStream = null;
        }
    }

    /**
     * Video frame processing loop
     */
    function startScanLoop(videoElement, onScanSuccess) {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        let isProcessing = false;

        async function tick() {
            if (!activeStream || videoElement.paused || videoElement.ended) {
                return;
            }

            if (videoElement.readyState >= videoElement.HAVE_CURRENT_DATA && !isProcessing) {
                isProcessing = true;
                const vw = videoElement.videoWidth;
                const vh = videoElement.videoHeight;

                if (vw > 0 && vh > 0) {
                    const maxDim = 800;
                    const scale = Math.min(1, maxDim / Math.max(vw, vh));
                    canvas.width = Math.round(vw * scale);
                    canvas.height = Math.round(vh * scale);
                    ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);

                    try {
                        const result = await scanCanvas(canvas);
                        if (result && result.rawValue) {
                            stopCamera();
                            if (onScanSuccess) onScanSuccess(result.rawValue);
                            return;
                        }
                    } catch (e) {
                        // Continue loop on next frame
                    } finally {
                        isProcessing = false;
                    }
                } else {
                    isProcessing = false;
                }
            }

            scanAnimationId = requestAnimationFrame(tick);
        }

        scanAnimationId = requestAnimationFrame(tick);
    }

    /**
     * Scan an uploaded Image file, Blob, or Canvas
     */
    async function scanImageFile(fileOrBlob) {
        if (!fileOrBlob) {
            throw new Error("No image file provided.");
        }

        // If it's already an HTMLCanvasElement
        if (typeof HTMLCanvasElement !== 'undefined' && fileOrBlob instanceof HTMLCanvasElement) {
            const res = await scanCanvas(fileOrBlob);
            if (res && res.rawValue) return res.rawValue;
            throw new Error("No QR code detected in the canvas.");
        }

        // If it's ImageData
        if (typeof ImageData !== 'undefined' && fileOrBlob instanceof ImageData) {
            const res = scanImageData(fileOrBlob);
            if (res && res.rawValue) return res.rawValue;
            throw new Error("No QR code detected in the image data.");
        }

        // Fast path: createImageBitmap (browser API)
        if (typeof createImageBitmap === 'function' && typeof document !== 'undefined') {
            try {
                const bitmap = await createImageBitmap(fileOrBlob);
                const canvas = document.createElement('canvas');
                canvas.width = bitmap.width;
                canvas.height = bitmap.height;
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(bitmap, 0, 0);
                const res = await scanCanvas(canvas);
                if (res && res.rawValue) {
                    return res.rawValue;
                }
            } catch (e) {
                // Fallback to FileReader/Image
            }
        }

        // Universal FileReader + Image element fallback
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                const img = new Image();
                img.onload = async () => {
                    const canvas = document.createElement('canvas');
                    canvas.width = img.naturalWidth || img.width;
                    canvas.height = img.naturalHeight || img.height;
                    const ctx = canvas.getContext('2d', { willReadFrequently: true });
                    ctx.drawImage(img, 0, 0);

                    try {
                        const result = await scanCanvas(canvas);
                        if (result && result.rawValue) {
                            resolve(result.rawValue);
                        } else {
                            reject(new Error("No QR code detected in the uploaded image."));
                        }
                    } catch (err) {
                        reject(err);
                    }
                };
                img.onerror = () => reject(new Error("Failed to load image file."));
                img.src = e.target.result;
            };
            reader.onerror = () => reject(new Error("Failed to read image data."));
            reader.readAsDataURL(fileOrBlob);
        });
    }

    return {
        startCamera,
        stopCamera,
        scanCanvas,
        scanImageData,
        scanImageFile,
        decodeBitMatrix,
        hasNativeScanner: !!barcodeDetector
    };
}));
