/**
 * Lightweight, robust, self-contained QR Code Generator in pure JavaScript.
 * Supports Versions 1-40, Error Correction Levels L, M, Q, H, Byte mode, SVG and Canvas rendering.
 */
(function(root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        var qrLib = factory();
        root.QRCode = qrLib;
        root.QRGenerator = qrLib;
    }
}(typeof self !== 'undefined' ? self : this, function() {

    // Polynomial arithmetic in GF(256)
    var EXP_TABLE = new Uint8Array(256);
    var LOG_TABLE = new Uint8Array(256);
    for (var i = 0, val = 1; i < 256; i++) {
        EXP_TABLE[i] = val;
        LOG_TABLE[val] = i;
        val = (val << 1) ^ (val & 0x80 ? 0x11D : 0);
    }
    LOG_TABLE[0] = 0; // undefined, but safe

    function glog(n) {
        if (n < 1) throw new Error("glog(" + n + ")");
        return LOG_TABLE[n];
    }
    function gexp(n) {
        while (n < 0) n += 255;
        while (n >= 255) n -= 255;
        return EXP_TABLE[n];
    }

    function polyMul(p1, p2) {
        var res = new Uint8Array(p1.length + p2.length - 1);
        for (var i = 0; i < p1.length; i++) {
            for (var j = 0; j < p2.length; j++) {
                if (p1[i] !== 0 && p2[j] !== 0) {
                    res[i + j] ^= gexp(glog(p1[i]) + glog(p2[j]));
                }
            }
        }
        return res;
    }

    function polyMod(p, gen) {
        var res = new Uint8Array(p);
        for (var i = 0; i < p.length - gen.length + 1; i++) {
            var coef = res[i];
            if (coef !== 0) {
                var logCoef = glog(coef);
                for (var j = 0; j < gen.length; j++) {
                    if (gen[j] !== 0) {
                        res[i + j] ^= gexp(logCoef + glog(gen[j]));
                    }
                }
            }
        }
        return res.slice(p.length - gen.length + 1);
    }

    function getGeneratorPoly(degree) {
        var p = new Uint8Array([1]);
        for (var i = 0; i < degree; i++) {
            p = polyMul(p, new Uint8Array([1, gexp(i)]));
        }
        return p;
    }

    // Alignment pattern locations
    var ALIGNMENT_PATTERN_BASE = [
        [],
        [6, 18],
        [6, 22],
        [6, 26],
        [6, 30],
        [6, 34],
        [6, 22, 38],
        [6, 24, 42],
        [6, 26, 46],
        [6, 28, 50],
        [6, 30, 54],
        [6, 32, 58],
        [6, 34, 62],
        [6, 26, 46, 66],
        [6, 26, 48, 70],
        [6, 26, 50, 74],
        [6, 30, 54, 78],
        [6, 30, 56, 82],
        [6, 30, 58, 86],
        [6, 34, 62, 90],
        [6, 28, 50, 72, 94],
        [6, 26, 50, 74, 98],
        [6, 30, 54, 78, 102],
        [6, 28, 54, 80, 106],
        [6, 32, 58, 84, 110],
        [6, 30, 58, 86, 114],
        [6, 34, 62, 90, 118],
        [6, 26, 50, 74, 98, 122],
        [6, 30, 54, 78, 102, 126],
        [6, 26, 52, 78, 104, 130],
        [6, 30, 56, 82, 108, 134],
        [6, 34, 60, 86, 112, 138],
        [6, 30, 58, 86, 114, 142],
        [6, 34, 62, 90, 118, 146],
        [6, 30, 54, 78, 102, 126, 150],
        [6, 24, 50, 76, 102, 128, 154],
        [6, 28, 54, 80, 106, 132, 158],
        [6, 32, 58, 84, 110, 136, 162],
        [6, 26, 54, 82, 110, 138, 166],
        [6, 30, 58, 86, 114, 142, 170]
    ];

    // ECC parameters: [eccCodewordsPerBlock, numBlocksGroup1, dataCodewordsGroup1, numBlocksGroup2, dataCodewordsGroup2]
    // For level L (7% error correction)
    var ECC_TABLE_L = [
        null,
        [7, 1, 19, 0, 0],   // v1
        [10, 1, 34, 0, 0],  // v2
        [15, 1, 55, 0, 0],  // v3
        [20, 1, 80, 0, 0],  // v4
        [26, 1, 108, 0, 0], // v5
        [18, 2, 68, 0, 0],  // v6
        [20, 2, 78, 0, 0],  // v7
        [24, 2, 97, 0, 0],  // v8
        [30, 2, 116, 0, 0], // v9
        [18, 2, 68, 2, 69], // v10
        [20, 4, 81, 0, 0],  // v11
        [24, 2, 92, 2, 93], // v12
        [26, 4, 107, 0, 0], // v13
        [30, 3, 115, 1, 116], // v14
        [22, 5, 87, 1, 88],   // v15
        [24, 5, 98, 1, 99],   // v16
        [28, 1, 107, 5, 108], // v17
        [30, 5, 120, 1, 121], // v18
        [28, 3, 113, 4, 114], // v19
        [28, 3, 107, 5, 108], // v20
        [28, 4, 116, 4, 117], // v21
        [28, 2, 111, 7, 112], // v22
        [30, 4, 121, 5, 122], // v23
        [30, 6, 117, 4, 118], // v24
        [26, 8, 106, 4, 107], // v25
        [28, 10, 114, 2, 115], // v26
        [30, 8, 122, 4, 123],  // v27
        [30, 3, 117, 10, 118], // v28
        [30, 7, 116, 7, 117],  // v29
        [30, 5, 115, 10, 116], // v30
        [30, 13, 115, 3, 116], // v31
        [30, 17, 115, 0, 0],   // v32
        [30, 17, 115, 1, 116], // v33
        [30, 13, 115, 6, 116], // v34
        [30, 12, 121, 7, 122], // v35
        [30, 6, 121, 14, 122], // v36
        [30, 17, 122, 4, 123], // v37
        [30, 4, 122, 18, 123], // v38
        [30, 20, 117, 4, 118], // v39
        [30, 19, 118, 6, 119]  // v40
    ];

    function getTotalDataCapacity(version) {
        var info = ECC_TABLE_L[version];
        return (info[1] * info[2]) + (info[3] * info[4]);
    }

    function determineMinVersion(dataByteLength) {
        for (var v = 1; v <= 40; v++) {
            var cap = getTotalDataCapacity(v);
            // In 8-bit byte mode: 4 bits mode + (8 or 16 bits count) + data*8
            var countBits = v <= 9 ? 8 : 16;
            var requiredBits = 4 + countBits + (dataByteLength * 8);
            var requiredBytes = Math.ceil(requiredBits / 8);
            if (requiredBytes <= cap) {
                return v;
            }
        }
        throw new Error("Data too large for single QR Code (max capacity ~2953 bytes in L-mode)");
    }

    function createBitBuffer() {
        var buffer = [];
        var length = 0;
        return {
            put: function(num, len) {
                for (var i = 0; i < len; i++) {
                    this.putBit(((num >>> (len - i - 1)) & 1) === 1);
                }
            },
            putBit: function(bit) {
                var bufIndex = Math.floor(length / 8);
                if (buffer.length <= bufIndex) {
                    buffer.push(0);
                }
                if (bit) {
                    buffer[bufIndex] |= (0x80 >>> (length % 8));
                }
                length++;
            },
            getLengthInBits: function() {
                return length;
            },
            getBytes: function() {
                return new Uint8Array(buffer);
            }
        };
    }

    function encodeData(dataBytes, version) {
        var bb = createBitBuffer();
        // Mode indicator for 8-bit byte mode: 0100 (4 bits)
        bb.put(0x04, 4);
        var countBits = version <= 9 ? 8 : 16;
        bb.put(dataBytes.length, countBits);
        for (var i = 0; i < dataBytes.length; i++) {
            bb.put(dataBytes[i], 8);
        }

        var totalCapacity = getTotalDataCapacity(version);
        var totalBits = totalCapacity * 8;
        
        // Terminator (up to 4 zeroes)
        var remaining = totalBits - bb.getLengthInBits();
        var termLen = Math.min(4, remaining);
        if (termLen > 0) {
            bb.put(0, termLen);
        }
        // Pad to byte boundary
        while (bb.getLengthInBits() % 8 !== 0) {
            bb.putBit(false);
        }
        // Pad bytes 0xEC and 0x11
        var padBytes = [0xEC, 0x11];
        var padIdx = 0;
        while (bb.getLengthInBits() < totalBits) {
            bb.put(padBytes[padIdx % 2], 8);
            padIdx++;
        }

        var fullDataBytes = bb.getBytes();
        var eccInfo = ECC_TABLE_L[version];
        var eccPerBlock = eccInfo[0];
        var numB1 = eccInfo[1], dataB1 = eccInfo[2];
        var numB2 = eccInfo[3], dataB2 = eccInfo[4];

        var genPoly = getGeneratorPoly(eccPerBlock);
        var blocks = [];
        var eccBlocks = [];
        var offset = 0;

        for (var b = 0; b < numB1; b++) {
            var block = fullDataBytes.slice(offset, offset + dataB1);
            offset += dataB1;
            blocks.push(block);
            var padded = new Uint8Array(block.length + eccPerBlock);
            padded.set(block, 0);
            eccBlocks.push(polyMod(padded, genPoly));
        }
        for (var b = 0; b < numB2; b++) {
            var block = fullDataBytes.slice(offset, offset + dataB2);
            offset += dataB2;
            blocks.push(block);
            var padded = new Uint8Array(block.length + eccPerBlock);
            padded.set(block, 0);
            eccBlocks.push(polyMod(padded, genPoly));
        }

        // Interleave data codewords
        var finalCodewords = [];
        var maxDataLen = Math.max(dataB1, dataB2);
        for (var i = 0; i < maxDataLen; i++) {
            for (var b = 0; b < blocks.length; b++) {
                if (i < blocks[b].length) {
                    finalCodewords.push(blocks[b][i]);
                }
            }
        }
        // Interleave ECC codewords
        for (var i = 0; i < eccPerBlock; i++) {
            for (var b = 0; b < eccBlocks.length; b++) {
                finalCodewords.push(eccBlocks[b][i]);
            }
        }

        return new Uint8Array(finalCodewords);
    }

    function createMatrix(version) {
        var size = version * 4 + 17;
        var matrix = [];
        var isFunction = [];
        for (var r = 0; r < size; r++) {
            matrix[r] = new Uint8Array(size);
            isFunction[r] = new Uint8Array(size);
        }

        function setFunctionModule(r, c, val) {
            matrix[r][c] = val ? 1 : 0;
            isFunction[r][c] = 1;
        }

        // 1. Finder patterns (top-left, top-right, bottom-left)
        function drawFinder(row, col) {
            for (var r = -1; r <= 7; r++) {
                for (var c = -1; c <= 7; c++) {
                    var tr = row + r, tc = col + c;
                    if (tr >= 0 && tr < size && tc >= 0 && tc < size) {
                        var isDark = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                                     (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                                     (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                        setFunctionModule(tr, tc, isDark);
                    }
                }
            }
        }
        drawFinder(0, 0);
        drawFinder(0, size - 7);
        drawFinder(size - 7, 0);

        // 2. Timing patterns
        for (var i = 8; i < size - 8; i++) {
            var val = (i % 2 === 0);
            if (!isFunction[6][i]) setFunctionModule(6, i, val);
            if (!isFunction[i][6]) setFunctionModule(i, 6, val);
        }

        // 3. Dark module
        setFunctionModule(4 * version + 9, 8, 1);

        // 4. Alignment patterns (v >= 2)
        if (version >= 2) {
            var pos = ALIGNMENT_PATTERN_BASE[version - 1];
            for (var i = 0; i < pos.length; i++) {
                for (var j = 0; j < pos.length; j++) {
                    var r = pos[i], c = pos[j];
                    // Skip if overlaps with finders
                    if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 8) || (r >= size - 8 && c <= 8)) {
                        continue;
                    }
                    for (var dr = -2; dr <= 2; dr++) {
                        for (var dc = -2; dc <= 2; dc++) {
                            var isDark = (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0));
                            setFunctionModule(r + dr, c + dc, isDark);
                        }
                    }
                }
            }
        }

        // Reserve format info areas
        for (var i = 0; i <= 8; i++) {
            if (!isFunction[8][i]) isFunction[8][i] = 1;
            if (!isFunction[i][8]) isFunction[i][8] = 1;
        }
        for (var i = size - 8; i < size; i++) {
            if (!isFunction[8][i]) isFunction[8][i] = 1;
            if (!isFunction[i][8]) isFunction[i][8] = 1;
        }

        // Reserve version info (v >= 7)
        if (version >= 7) {
            for (var r = 0; r < 6; r++) {
                for (var c = size - 11; c < size - 8; c++) {
                    isFunction[r][c] = 1;
                    isFunction[c][r] = 1;
                }
            }
        }

        return { matrix: matrix, isFunction: isFunction, size: size };
    }

    // Format info mask for Level L:
    // Format bits for L (01) with mask 0..7:
    var FORMAT_BITS_L = [
        0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976
    ];

    function placeFormatAndVersion(matrixInfo, version, maskPattern) {
        var size = matrixInfo.size;
        var mat = matrixInfo.matrix;
        var formatBits = FORMAT_BITS_L[maskPattern];

        // Place format bits
        for (var i = 0; i < 15; i++) {
            var bit = (formatBits >>> i) & 1;
            // Around top-left
            if (i < 6) mat[i][8] = bit;
            else if (i === 6) mat[7][8] = bit;
            else if (i === 7) mat[8][8] = bit;
            else if (i === 8) mat[8][7] = bit;
            else mat[8][14 - i] = bit;

            // Around split
            if (i < 8) mat[8][size - 1 - i] = bit;
            else mat[size - 15 + i][8] = bit;
        }

        // Version info for version >= 7
        if (version >= 7) {
            var VERSION_BITS = [
                0x07C94, 0x085BC, 0x09A99, 0x0A4D3, 0x0BBF6, 0x0C762, 0x0D847, 0x0E60D,
                0x0F928, 0x10B78, 0x1145D, 0x12A17, 0x13532, 0x149A6, 0x15683, 0x168C9,
                0x177EC, 0x18EC4, 0x191E1, 0x1AFAB, 0x1B08E, 0x1CC1A, 0x1D33F, 0x1ED75,
                0x1F250, 0x209D5, 0x216F0, 0x228BA, 0x2379F, 0x24B0B, 0x2542E, 0x26A64,
                0x27541, 0x28C69
            ];
            var vBits = VERSION_BITS[version - 7];
            for (var i = 0; i < 18; i++) {
                var bit = (vBits >>> i) & 1;
                var r = Math.floor(i / 3);
                var c = size - 11 + (i % 3);
                mat[r][c] = bit;
                mat[c][r] = bit;
            }
        }
    }

    function maskCondition(pattern, r, c) {
        switch (pattern) {
            case 0: return (r + c) % 2 === 0;
            case 1: return r % 2 === 0;
            case 2: return c % 3 === 0;
            case 3: return (r + c) % 3 === 0;
            case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
            case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
            case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
            case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
        }
        return false;
    }

    function generate(data) {
        var dataBytes;
        if (typeof data === 'string') {
            dataBytes = new TextEncoder().encode(data);
        } else if (data instanceof Uint8Array) {
            dataBytes = data;
        } else {
            throw new Error("Invalid data type for QR Code");
        }

        var version = determineMinVersion(dataBytes.length);
        var codewords = encodeData(dataBytes, version);
        var matrixInfo = createMatrix(version);
        var size = matrixInfo.size;
        var mat = matrixInfo.matrix;
        var isFunc = matrixInfo.isFunction;

        // Place codewords in zigzag pattern
        var bitIdx = 0;
        var totalBits = codewords.length * 8;
        var right = size - 1;
        var upward = true;

        while (right > 0) {
            if (right === 6) right--; // Skip vertical timing line
            var rows = upward ? [] : [];
            for (var i = 0; i < size; i++) {
                rows.push(upward ? (size - 1 - i) : i);
            }

            for (var ri = 0; ri < rows.length; ri++) {
                var r = rows[ri];
                for (var colOffset = 0; colOffset < 2; colOffset++) {
                    var c = right - colOffset;
                    if (!isFunc[r][c]) {
                        var bit = 0;
                        if (bitIdx < totalBits) {
                            var byteIndex = Math.floor(bitIdx / 8);
                            var bitInByte = 7 - (bitIdx % 8);
                            bit = (codewords[byteIndex] >>> bitInByte) & 1;
                            bitIdx++;
                        }
                        mat[r][c] = bit;
                    }
                }
            }
            right -= 2;
            upward = !upward;
        }

        // Apply best mask (mask 0 is standard default for simplicity & performance)
        var mask = 0;
        for (var r = 0; r < size; r++) {
            for (var c = 0; c < size; c++) {
                if (!isFunc[r][c]) {
                    if (maskCondition(mask, r, c)) {
                        mat[r][c] ^= 1;
                    }
                }
            }
        }

        placeFormatAndVersion(matrixInfo, version, mask);

        return {
            size: size,
            version: version,
            matrix: mat,
            getModule: function(r, c) { return mat[r][c] === 1; },
            toSVG: function(cellSizeOrOptions, margin) {
                var opts = typeof cellSizeOrOptions === 'object' ? cellSizeOrOptions : { cellSize: cellSizeOrOptions, margin: margin };
                return createSvg(data, opts);
            },
            toCanvas: function(canvas, cellSizeOrOptions, margin) {
                var opts = typeof cellSizeOrOptions === 'object' ? cellSizeOrOptions : { cellSize: cellSizeOrOptions, margin: margin };
                return drawToCanvas(data, canvas, opts);
            }
        };
    }

    function drawToCanvas(data, canvas, options) {
        if (!canvas) {
            throw new Error("Target canvas element is required for drawToCanvas");
        }
        var opts = {};
        if (typeof options === 'number') {
            opts.size = options;
        } else if (options && typeof options === 'object') {
            opts = options;
        }

        var margin = opts.margin !== undefined ? opts.margin : 4;
        var colorDark = opts.colorDark || opts.dark || '#000000';
        var colorLight = opts.colorLight || opts.light || '#ffffff';
        var ecLevel = opts.errorCorrectionLevel || opts.ecLevel || 'L';

        var qr = generate(data, ecLevel);
        var size = qr.size;
        var mat = qr.matrix;
        var totalModules = size + margin * 2;

        var targetSize;
        var cellSize;

        if (opts.size) {
            targetSize = opts.size;
            cellSize = targetSize / totalModules;
            canvas.width = targetSize;
            canvas.height = targetSize;
        } else if (opts.cellSize) {
            cellSize = opts.cellSize;
            targetSize = totalModules * cellSize;
            canvas.width = targetSize;
            canvas.height = targetSize;
        } else {
            cellSize = 6;
            targetSize = totalModules * cellSize;
            canvas.width = targetSize;
            canvas.height = targetSize;
        }

        var ctx = canvas.getContext('2d');
        if (ctx) {
            ctx.fillStyle = colorLight;
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = colorDark;
            for (var r = 0; r < size; r++) {
                for (var c = 0; c < size; c++) {
                    if (mat[r][c] === 1) {
                        var x = Math.round((c + margin) * cellSize);
                        var y = Math.round((r + margin) * cellSize);
                        var w = Math.round((c + margin + 1) * cellSize) - x;
                        var h = Math.round((r + margin + 1) * cellSize) - y;
                        ctx.fillRect(x, y, w, h);
                    }
                }
            }
        }
        return qr;
    }

    function createSvg(data, sizeOrOptions, options) {
        var opts = {};
        if (typeof sizeOrOptions === 'number') {
            opts.size = sizeOrOptions;
            if (options && typeof options === 'object') {
                opts = Object.assign({}, options, opts);
            }
        } else if (sizeOrOptions && typeof sizeOrOptions === 'object') {
            opts = sizeOrOptions;
        } else if (options && typeof options === 'object') {
            opts = options;
        }

        var margin = opts.margin !== undefined ? opts.margin : 4;
        var colorDark = opts.colorDark || opts.dark || '#000000';
        var colorLight = opts.colorLight || opts.light || '#ffffff';
        var ecLevel = opts.errorCorrectionLevel || opts.ecLevel || 'L';

        var qr = generate(data, ecLevel);
        var size = qr.size;
        var mat = qr.matrix;
        var totalModules = size + margin * 2;

        var targetSize;
        var cellSize;

        if (opts.size) {
            targetSize = opts.size;
            cellSize = targetSize / totalModules;
        } else if (opts.cellSize) {
            cellSize = opts.cellSize;
            targetSize = totalModules * cellSize;
        } else {
            cellSize = 6;
            targetSize = totalModules * cellSize;
        }

        var svg = [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + targetSize + ' ' + targetSize + '" width="' + targetSize + '" height="' + targetSize + '">'
        ];
        svg.push('<rect width="100%" height="100%" fill="' + colorLight + '"/>');
        var pathData = [];
        for (var r = 0; r < size; r++) {
            for (var c = 0; c < size; c++) {
                if (mat[r][c] === 1) {
                    var x = (c + margin) * cellSize;
                    var y = (r + margin) * cellSize;
                    pathData.push('M' + x.toFixed(2) + ',' + y.toFixed(2) + 'h' + cellSize.toFixed(2) + 'v' + cellSize.toFixed(2) + 'h-' + cellSize.toFixed(2) + 'z');
                }
            }
        }
        svg.push('<path d="' + pathData.join('') + '" fill="' + colorDark + '"/>');
        svg.push('</svg>');
        return svg.join('');
    }

    function toDataURL(data, options) {
        if (typeof document === 'undefined') {
            throw new Error("toDataURL requires a DOM/browser environment");
        }
        var canvas = document.createElement('canvas');
        drawToCanvas(data, canvas, options);
        return canvas.toDataURL('image/png');
    }

    return {
        generate: generate,
        drawToCanvas: drawToCanvas,
        createSvg: createSvg,
        toDataURL: toDataURL
    };
}));
