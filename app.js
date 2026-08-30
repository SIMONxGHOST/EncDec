/**
 * EncDec Studio Pro — Advanced Application Controller (v5.1.0)
 * =========================================================================
 * Handles UI interactions, 10-Tier Web Crypto AES-256-GCM & Memory-Hard KDFs,
 * Keyfile 2-Factor authentication, QR Studio, File Security Vault, & Benchmarks.
 */

(function() {
    'use strict';

    // App State
    let isLiveSync = false;
    let useEnvelope = true;
    let debounceTimer = null;
    let selectedFile = null;
    let loadedKeyfileBytes = null;
    let loadedKeyfileName = "";
    let activityLogs = [];

    // DOM References
    const el = {
        themeToggleBtn: document.getElementById('themeToggleBtn'),
        themeIcon: document.getElementById('themeIcon'),
        navTabs: document.querySelectorAll('.nav-tab'),
        tabPanes: document.querySelectorAll('.tab-pane'),
        
        // Master Password Bar
        masterPassword: document.getElementById('masterPassword'),
        togglePasswordBtn: document.getElementById('togglePasswordBtn'),
        generatePasswordBtn: document.getElementById('generatePasswordBtn'),
        keyTypeSelect: document.getElementById('keyTypeSelect'),
        useEnvelopeToggle: document.getElementById('useEnvelopeToggle'),
        liveSyncToggle: document.getElementById('liveSyncToggle'),
        
        // Keyfile / 2FA Token
        loadKeyfileBtn: document.getElementById('loadKeyfileBtn'),
        keyfileInput: document.getElementById('keyfileInput'),
        keyfileBadge: document.getElementById('keyfileBadge'),
        keyfileNameSpan: document.getElementById('keyfileNameSpan'),
        removeKeyfileBtn: document.getElementById('removeKeyfileBtn'),
        
        // Password Meter
        passwordMeterFill: document.getElementById('passwordMeterFill'),
        passwordEntropyLabel: document.getElementById('passwordEntropyLabel'),
        passwordCrackTimeLabel: document.getElementById('passwordCrackTimeLabel'),
        kdfLabelBadge: document.getElementById('kdfLabelBadge'),
        
        // Text Cryptography
        plainTextInput: document.getElementById('plainTextInput'),
        cipherTextInput: document.getElementById('cipherTextInput'),
        encryptBtn: document.getElementById('encryptBtn'),
        decryptBtn: document.getElementById('decryptBtn'),
        swapTextBtn: document.getElementById('swapTextBtn'),
        
        // Plaintext Toolbar
        pastePlainBtn: document.getElementById('pastePlainBtn'),
        copyPlainBtn: document.getElementById('copyPlainBtn'),
        loadPlainBtn: document.getElementById('loadPlainBtn'),
        plainFileInput: document.getElementById('plainFileInput'),
        downloadPlainBtn: document.getElementById('downloadPlainBtn'),
        clearPlainBtn: document.getElementById('clearPlainBtn'),
        plainStats: document.getElementById('plainStats'),
        
        // Ciphertext Toolbar
        openQrBtn: document.getElementById('openQrBtn'),
        pasteCipherBtn: document.getElementById('pasteCipherBtn'),
        copyCipherBtn: document.getElementById('copyCipherBtn'),
        downloadCipherBtn: document.getElementById('downloadCipherBtn'),
        clearCipherBtn: document.getElementById('clearCipherBtn'),
        cipherStats: document.getElementById('cipherStats'),
        payloadBadge: document.getElementById('payloadBadge'),
        
        // Status & Beacon
        statusBeacon: document.getElementById('statusBeacon'),
        statusMessage: document.getElementById('statusMessage'),
        statusDetails: document.getElementById('statusDetails'),
        
        // File Vault
        fileDropzone: document.getElementById('fileDropzone'),
        fileInput: document.getElementById('fileInput'),
        fileInfoCard: document.getElementById('fileInfoCard'),
        fileNameDisplay: document.getElementById('fileNameDisplay'),
        fileSizeDisplay: document.getElementById('fileSizeDisplay'),
        fileClearBtn: document.getElementById('fileClearBtn'),
        filePasswordInput: document.getElementById('filePasswordInput'),
        copyMasterToFilePwdBtn: document.getElementById('copyMasterToFilePwdBtn'),
        encryptFileBtn: document.getElementById('encryptFileBtn'),
        decryptFileBtn: document.getElementById('decryptFileBtn'),
        fileProgressBar: document.getElementById('fileProgressBar'),
        fileProgressFill: document.getElementById('fileProgressFill'),
        fileProgressText: document.getElementById('fileProgressText'),
        
        // QR Code Studio
        qrSourceInput: document.getElementById('qrSourceInput'),
        qrZlibCompress: document.getElementById('qrZlibCompress'),
        qrCanvas: document.getElementById('qrCanvas'),
        qrPayloadStats: document.getElementById('qrPayloadStats'),
        downloadQrPngBtn: document.getElementById('downloadQrPngBtn'),
        downloadQrSvgBtn: document.getElementById('downloadQrSvgBtn'),
        copyQrImageBtn: document.getElementById('copyQrImageBtn'),
        copyQrPayloadBtn: document.getElementById('copyQrPayloadBtn'),
        
        // QR Scanner
        cameraVideo: document.getElementById('cameraVideo'),
        startCameraBtn: document.getElementById('startCameraBtn'),
        stopCameraBtn: document.getElementById('stopCameraBtn'),
        qrImageDropzone: document.getElementById('qrImageDropzone'),
        qrImageInput: document.getElementById('qrImageInput'),
        qrScanResultCard: document.getElementById('qrScanResultCard'),
        qrScanResultText: document.getElementById('qrScanResultText'),
        sendScanToDecryptBtn: document.getElementById('sendScanToDecryptBtn'),
        
        // Security Benchmark
        keyConfigTable: document.getElementById('keyConfigTable'),
        runBenchmarkBtn: document.getElementById('runBenchmarkBtn'),
        
        // Pass Gen Modal
        passGenModal: document.getElementById('passGenModal'),
        closePassGenModalBtn: document.getElementById('closePassGenModalBtn'),
        genModeDicewareBtn: document.getElementById('genModeDicewareBtn'),
        genModeCharsBtn: document.getElementById('genModeCharsBtn'),
        dicewareOptionsBox: document.getElementById('dicewareOptionsBox'),
        charsOptionsBox: document.getElementById('charsOptionsBox'),
        genDicewareCount: document.getElementById('genDicewareCount'),
        genDicewareCountVal: document.getElementById('genDicewareCountVal'),
        genDicewareSep: document.getElementById('genDicewareSep'),
        genPassLength: document.getElementById('genPassLength'),
        genPassLengthVal: document.getElementById('genPassLengthVal'),
        genOptUpper: document.getElementById('genOptUpper'),
        genOptLower: document.getElementById('genOptLower'),
        genOptNums: document.getElementById('genOptNums'),
        genOptSpecial: document.getElementById('genOptSpecial'),
        modalGeneratedPassInput: document.getElementById('modalGeneratedPassInput'),
        modalRegenPassBtn: document.getElementById('modalRegenPassBtn'),
        applyGeneratedPassBtn: document.getElementById('applyGeneratedPassBtn'),
        
        // Logs
        openLogBtn: document.getElementById('openLogBtn'),
        logModal: document.getElementById('logModal'),
        closeLogModalBtn: document.getElementById('closeLogModalBtn'),
        logContainer: document.getElementById('logContainer'),
        clearLogBtn: document.getElementById('clearLogBtn'),
        exportLogBtn: document.getElementById('exportLogBtn'),
        
        toastContainer: document.getElementById('toastContainer')
    };

    let passGenMode = 'diceware';

    // =========================================================================
    // Initialization
    // =========================================================================
    function init() {
        initTheme();
        initNavigation();
        initKeyConfigs();
        initKeyfileListeners();
        initPasswordListeners();
        initTextPanelListeners();
        initFileListeners();
        initQrStudio();
        initSecurityTable();
        initPasswordModal();
        initLogModal();
        updateStatus("EncDec Studio Pro (100% AES-256-GCM) Ready", "idle");
        logActivity("Application initialized in 10-Tier AES-256-GCM Vault Mode");
    }

    // Theme Switcher
    function initTheme() {
        const savedTheme = localStorage.getItem('encdec_theme') || 'dark';
        setTheme(savedTheme);
        el.themeToggleBtn.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme') || 'dark';
            setTheme(current === 'dark' ? 'light' : 'dark');
        });
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('encdec_theme', theme);
        if (theme === 'dark') {
            el.themeIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>`;
        } else {
            el.themeIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>`;
        }
    }

    // Navigation Tabs
    function initNavigation() {
        el.navTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.getAttribute('data-tab');
                switchTab(targetTab);
            });
        });
    }

    function switchTab(tabId) {
        el.navTabs.forEach(t => t.classList.toggle('active', t.getAttribute('data-tab') === tabId));
        el.tabPanes.forEach(p => p.classList.toggle('active', p.id === `${tabId}Pane`));
        if (tabId === 'qr' && el.cipherTextInput.value.trim()) {
            el.qrSourceInput.value = el.cipherTextInput.value.trim();
            renderQrCode();
        } else if (tabId !== 'qr') {
            if (typeof QRScanner !== 'undefined' && QRScanner.stopCamera) {
                QRScanner.stopCamera();
                if (el.startCameraBtn) el.startCameraBtn.style.display = 'inline-flex';
                if (el.stopCameraBtn) el.stopCameraBtn.style.display = 'none';
            }
        }
    }

    // Key Configs Dropdown
    function initKeyConfigs() {
        el.keyTypeSelect.innerHTML = '';
        Object.entries(EncDecCrypto.KEY_CONFIGS).forEach(([key, conf]) => {
            const opt = document.createElement('option');
            opt.value = key;
            opt.textContent = conf.label;
            el.keyTypeSelect.appendChild(opt);
        });
        el.keyTypeSelect.value = "Key 4"; // Default to Key 4 (High - 64MB Scrypt + AES-256-GCM)
        el.keyTypeSelect.addEventListener('change', () => {
            updateKdfBadge();
            if (isLiveSync) triggerLiveSync();
        });
        updateKdfBadge();
    }

    function updateKdfBadge() {
        const conf = EncDecCrypto.getKeyConfig(el.keyTypeSelect.value);
        const memMb = Math.round((conf.scryptN * conf.scryptR * 128) / (1024 * 1024));
        el.kdfLabelBadge.textContent = `Scrypt (${memMb}MB RAM) + AES-256-GCM AEAD`;
        el.kdfLabelBadge.style.color = "var(--accent-blue)";
    }

    // Keyfile Listeners
    function initKeyfileListeners() {
        el.loadKeyfileBtn.addEventListener('click', () => el.keyfileInput.click());

        el.keyfileInput.addEventListener('change', async (e) => {
            if (e.target.files && e.target.files.length > 0) {
                const file = e.target.files[0];
                const buffer = await file.arrayBuffer();
                loadedKeyfileBytes = new Uint8Array(buffer);
                loadedKeyfileName = file.name;

                const hash = await EncDecCrypto.sha256(loadedKeyfileBytes);
                const hashHex = Array.from(hash.subarray(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');

                el.keyfileNameSpan.textContent = `🔑 ${file.name} (SHA: ${hashHex}...)`;
                el.keyfileBadge.style.display = 'inline-flex';
                el.loadKeyfileBtn.style.display = 'none';

                showToast(`Keyfile loaded: ${file.name}`, 'success');
                logActivity(`Keyfile attached (${file.name}, ${buffer.byteLength} bytes)`);
                if (isLiveSync) triggerLiveSync();
            }
        });

        el.removeKeyfileBtn.addEventListener('click', () => {
            loadedKeyfileBytes = null;
            loadedKeyfileName = "";
            el.keyfileInput.value = "";
            el.keyfileBadge.style.display = 'none';
            el.loadKeyfileBtn.style.display = 'inline-flex';
            showToast("Keyfile removed", "info");
            logActivity("Keyfile removed");
            if (isLiveSync) triggerLiveSync();
        });
    }

    // Password & Strength Meter
    function initPasswordListeners() {
        el.masterPassword.addEventListener('input', () => {
            const pwd = el.masterPassword.value;
            const evalResult = EncDecCrypto.evaluatePassword(pwd, true);
            
            el.passwordMeterFill.style.width = `${evalResult.percent}%`;
            el.passwordMeterFill.style.backgroundColor = evalResult.color;
            el.passwordEntropyLabel.textContent = `Strength: ${evalResult.label} (${evalResult.entropy} bits)`;
            el.passwordCrackTimeLabel.textContent = `Est. Crack Time: ${evalResult.crackTime}`;

            if (isLiveSync) triggerLiveSync();
        });

        el.togglePasswordBtn.addEventListener('click', () => {
            const isPassword = el.masterPassword.type === 'password';
            el.masterPassword.type = isPassword ? 'text' : 'password';
            el.togglePasswordBtn.setAttribute('title', isPassword ? 'Hide Password' : 'Show Password');
        });

        el.useEnvelopeToggle.addEventListener('change', (e) => {
            useEnvelope = e.target.checked;
            showToast(useEnvelope ? "ENC5 Envelope Enabled (Auto-Detect Tier)" : "Raw Base64 Payload Enabled");
        });

        el.liveSyncToggle.addEventListener('change', (e) => {
            isLiveSync = e.target.checked;
            showToast(isLiveSync ? "Live Real-Time Sync Enabled" : "Manual Execution Mode Enabled");
            if (isLiveSync) triggerLiveSync();
        });
    }

    // Text Panels & Encryption/Decryption
    function initTextPanelListeners() {
        el.plainTextInput.addEventListener('input', () => {
            updateStats();
            if (isLiveSync) debounceAction(handleEncrypt);
        });

        el.cipherTextInput.addEventListener('input', async () => {
            updateStats();
            await updatePayloadBadge();
            if (isLiveSync) debounceAction(handleDecrypt);
        });

        el.encryptBtn.addEventListener('click', handleEncrypt);
        el.decryptBtn.addEventListener('click', handleDecrypt);

        el.swapTextBtn.addEventListener('click', () => {
            const tmp = el.plainTextInput.value;
            el.plainTextInput.value = el.cipherTextInput.value;
            el.cipherTextInput.value = tmp;
            updateStats();
            updatePayloadBadge();
            showToast("Swapped text fields", "info");
        });

        // Plaintext toolbar
        el.pastePlainBtn.addEventListener('click', async () => {
            const text = await pasteFromClipboard();
            if (text !== null) {
                el.plainTextInput.value = text;
                updateStats();
                if (isLiveSync) handleEncrypt();
            }
        });
        el.copyPlainBtn.addEventListener('click', () => copyToClipboard(el.plainTextInput.value, "Plaintext copied"));
        el.loadPlainBtn.addEventListener('click', () => el.plainFileInput.click());
        el.plainFileInput.addEventListener('change', async (e) => {
            if (e.target.files && e.target.files.length > 0) {
                const text = await e.target.files[0].text();
                el.plainTextInput.value = text;
                updateStats();
                showToast(`Loaded ${e.target.files[0].name}`, 'success');
                if (isLiveSync) handleEncrypt();
            }
        });
        el.downloadPlainBtn.addEventListener('click', () => downloadFile(el.plainTextInput.value, 'decrypted_message.txt', 'text/plain'));
        el.clearPlainBtn.addEventListener('click', () => {
            el.plainTextInput.value = '';
            updateStats();
            updateStatus("Plaintext cleared", "idle");
        });

        // Ciphertext toolbar
        el.openQrBtn.addEventListener('click', () => {
            if (!el.cipherTextInput.value.trim()) {
                showToast("No ciphertext to encode into QR", "warning");
                return;
            }
            switchTab('qr');
        });
        el.pasteCipherBtn.addEventListener('click', async () => {
            const text = await pasteFromClipboard();
            if (text !== null) {
                const normalized = await EncDecCrypto.normalizeScannedText(text);
                el.cipherTextInput.value = normalized;
                updateStats();
                updatePayloadBadge();
                if (isLiveSync) handleDecrypt();
            }
        });
        el.copyCipherBtn.addEventListener('click', () => copyToClipboard(el.cipherTextInput.value, "Ciphertext copied"));
        el.downloadCipherBtn.addEventListener('click', () => {
            downloadFile(el.cipherTextInput.value, 'encrypted_message.enc', 'text/plain');
        });
        el.clearCipherBtn.addEventListener('click', () => {
            el.cipherTextInput.value = '';
            updateStats();
            updatePayloadBadge();
            updateStatus("Ciphertext cleared", "idle");
        });

        // Global hotkeys
        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleEncrypt();
            } else if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && e.shiftKey) {
                e.preventDefault();
                handleDecrypt();
            }
        });
    }

    function debounceAction(fn) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(fn, 250);
    }

    function triggerLiveSync() {
        if (el.plainTextInput.value.trim()) {
            debounceAction(handleEncrypt);
        } else if (el.cipherTextInput.value.trim()) {
            debounceAction(handleDecrypt);
        }
    }

    async function handleEncrypt() {
        const plain = el.plainTextInput.value.trim();
        const pwd = el.masterPassword.value;
        const keyType = el.keyTypeSelect.value;

        if (!plain) {
            if (!isLiveSync) showToast("Plaintext is empty", "warning");
            return;
        }
        if (!pwd) {
            updateStatus("Master Password is required to encrypt", "error");
            if (!isLiveSync) showToast("Please enter a Master Password", "error");
            return;
        }

        try {
            setBeacon('processing');
            const startTime = performance.now();
            const encrypted = await EncDecCrypto.encryptText(plain, pwd, keyType, useEnvelope, loadedKeyfileBytes);
            const elapsed = Math.round(performance.now() - startTime);

            el.cipherTextInput.value = encrypted;
            updateStats();
            await updatePayloadBadge();
            setBeacon('success');
            
            const conf = EncDecCrypto.getKeyConfig(keyType);
            updateStatus(`Text Encrypted in ${elapsed}ms (${conf.alias})`, "success", `AES-256-GCM AEAD | Scrypt Memory-Hard | Keyfile: ${loadedKeyfileBytes ? 'Active' : 'None'}`);
            logActivity(`Encrypted text (${conf.alias}, AES-256-GCM) - ${encrypted.length} chars in ${elapsed}ms`);
        } catch (err) {
            setBeacon('error');
            updateStatus(`Encryption Failed: ${err.message}`, "error");
        }
    }

    async function handleDecrypt() {
        const cipher = el.cipherTextInput.value.trim();
        const pwd = el.masterPassword.value;
        const keyType = el.keyTypeSelect.value;

        if (!cipher) {
            if (!isLiveSync) showToast("Ciphertext is empty", "warning");
            return;
        }
        if (!pwd) {
            updateStatus("Master Password is required to decrypt", "error");
            if (!isLiveSync) showToast("Please enter a Master Password", "error");
            return;
        }

        try {
            setBeacon('processing');
            const startTime = performance.now();
            const normalized = await EncDecCrypto.normalizeScannedText(cipher);
            const res = await EncDecCrypto.decryptText(normalized, pwd, keyType, loadedKeyfileBytes);
            const elapsed = Math.round(performance.now() - startTime);

            if (res.success) {
                el.plainTextInput.value = res.decryptedText;
                updateStats();
                setBeacon('success');
                updateStatus(`Decrypted Successfully in ${elapsed}ms (Matched: ${res.keyAlias})`, "success", `Cipher: ${res.cipher || 'AES-256-GCM'} | Integrity Verified`);
                showToast(`Decrypted with ${res.keyAlias}!`, "success");
                logActivity(`Decrypted text (Matched ${res.keyAlias}) in ${elapsed}ms`);
            } else {
                setBeacon('error');
                updateStatus("Decryption Failed: Incorrect password, keyfile, or corrupted data", "error");
                if (!isLiveSync) showToast("Decryption failed. Check password & Keyfile.", "error");
            }
        } catch (err) {
            setBeacon('error');
            updateStatus(`Decryption Error: ${err.message}`, "error");
        }
    }

    function updateStats() {
        const plain = el.plainTextInput.value;
        const cipher = el.cipherTextInput.value;
        
        const plainWords = plain.trim() ? plain.trim().split(/\s+/).length : 0;
        const plainBytes = new TextEncoder().encode(plain).length;
        el.plainStats.textContent = `${plain.length} chars | ${plainWords} words | ${formatBytes(plainBytes)}`;

        const cipherBytes = new TextEncoder().encode(cipher).length;
        el.cipherStats.textContent = `${cipher.length} chars | ${formatBytes(cipherBytes)}`;
    }

    async function updatePayloadBadge() {
        const cipher = el.cipherTextInput.value.trim();
        if (!cipher) {
            el.payloadBadge.textContent = 'Empty';
            el.payloadBadge.style.color = 'var(--text-dim)';
            return;
        }

        if (cipher.startsWith(EncDecCrypto.MAGIC_HEADER_V5)) {
            const alias = cipher.split(':')[1] || 'Vault';
            el.payloadBadge.textContent = `ENC5 (${alias})`;
            el.payloadBadge.style.color = 'var(--accent-blue)';
            return;
        }

        if (cipher.startsWith(EncDecCrypto.MAGIC_HEADER_V4)) {
            const alias = cipher.split(':')[1] || 'Envelope';
            el.payloadBadge.textContent = `ENC4 (${alias})`;
            el.payloadBadge.style.color = 'var(--accent-green)';
            return;
        }

        el.payloadBadge.textContent = 'Raw Ciphertext';
        el.payloadBadge.style.color = 'var(--accent-amber)';
    }

    // =========================================================================
    // File Security Vault
    // =========================================================================
    function initFileListeners() {
        el.fileDropzone.addEventListener('click', () => el.fileInput.click());
        el.fileDropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            el.fileDropzone.classList.add('dragover');
        });
        el.fileDropzone.addEventListener('dragleave', () => el.fileDropzone.classList.remove('dragover'));
        el.fileDropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            el.fileDropzone.classList.remove('dragover');
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFileSelected(e.dataTransfer.files[0]);
            }
        });

        el.fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleFileSelected(e.target.files[0]);
            }
        });

        el.fileClearBtn.addEventListener('click', () => {
            selectedFile = null;
            el.fileInput.value = '';
            el.fileInfoCard.style.display = 'none';
            el.fileDropzone.style.display = 'flex';
            el.fileProgressBar.style.display = 'none';
            updateStatus("File cleared", "idle");
        });

        el.copyMasterToFilePwdBtn.addEventListener('click', () => {
            if (!el.masterPassword.value) {
                showToast("Master Password is empty", "warning");
                return;
            }
            el.filePasswordInput.value = el.masterPassword.value;
            showToast("Copied Master Password to file vault", "info");
        });

        el.encryptFileBtn.addEventListener('click', handleEncryptFile);
        el.decryptFileBtn.addEventListener('click', handleDecryptFile);
    }

    function handleFileSelected(file) {
        selectedFile = file;
        el.fileNameDisplay.textContent = file.name;
        el.fileSizeDisplay.textContent = `${formatBytes(file.size)} • ${file.type || 'Binary Document'}`;
        el.fileDropzone.style.display = 'none';
        el.fileInfoCard.style.display = 'flex';
        el.fileProgressBar.style.display = 'none';
        updateStatus(`Loaded file: ${file.name} (${formatBytes(file.size)})`, "idle");
    }

    async function handleEncryptFile() {
        if (!selectedFile) return;
        const pwd = el.filePasswordInput.value || el.masterPassword.value;
        if (!pwd) {
            showToast("Password required for file encryption", "error");
            return;
        }

        const keyType = el.keyTypeSelect.value;
        try {
            showFileProgress(0, "Reading file bytes...");
            const buffer = await selectedFile.arrayBuffer();
            const fileBytes = new Uint8Array(buffer);

            const encryptedBytes = await EncDecCrypto.encryptFileBytes(
                fileBytes,
                pwd,
                keyType,
                (percent, msg) => showFileProgress(percent, msg),
                loadedKeyfileBytes,
                selectedFile.name
            );

            const outName = selectedFile.name.endsWith('.enc') ? `${selectedFile.name}.vault.enc` : `${selectedFile.name}.enc`;
            downloadBinaryFile(encryptedBytes, outName, 'application/octet-stream');
            
            showToast(`Encrypted ${selectedFile.name} successfully!`, "success");
            logActivity(`Encrypted file ${selectedFile.name} -> ${outName} (${formatBytes(encryptedBytes.length)})`);
            updateStatus(`File Vault: Encrypted ${selectedFile.name}`, "success");
        } catch (err) {
            showToast(`Encryption Failed: ${err.message}`, "error");
            updateStatus(`File Vault Error: ${err.message}`, "error");
        }
    }

    async function handleDecryptFile() {
        if (!selectedFile) return;
        const pwd = el.filePasswordInput.value || el.masterPassword.value;
        if (!pwd) {
            showToast("Password required for file decryption", "error");
            return;
        }

        const fallbackKey = el.keyTypeSelect.value;
        try {
            showFileProgress(0, "Reading container bytes...");
            const buffer = await selectedFile.arrayBuffer();
            const fileBytes = new Uint8Array(buffer);

            const res = await EncDecCrypto.decryptFileBytes(
                fileBytes,
                pwd,
                fallbackKey,
                (percent, msg) => showFileProgress(percent, msg),
                loadedKeyfileBytes
            );

            let outName = res.origName;
            if (!outName || outName === "decrypted_file") {
                outName = selectedFile.name.replace(/\.enc$/i, '') || 'decrypted_file.bin';
            }

            downloadBinaryFile(res.decryptedBytes, outName, 'application/octet-stream');
            showToast(`Decrypted ${outName} (${res.keyAlias})!`, "success");
            logActivity(`Decrypted file ${selectedFile.name} -> ${outName} (${formatBytes(res.decryptedBytes.length)})`);
            updateStatus(`File Vault: Decrypted ${outName}`, "success");
        } catch (err) {
            showToast(`Decryption Failed: ${err.message}`, "error");
            updateStatus(`File Vault Error: ${err.message}`, "error");
        }
    }

    function showFileProgress(percent, message) {
        el.fileProgressBar.style.display = 'block';
        el.fileProgressFill.style.width = `${percent}%`;
        el.fileProgressText.textContent = `${percent}% — ${message}`;
    }

    // =========================================================================
    // QR Code Studio & Scanner
    // =========================================================================
    function initQrStudio() {
        el.qrSourceInput.addEventListener('input', debounceAction(renderQrCode));
        el.qrZlibCompress.addEventListener('change', renderQrCode);

        el.downloadQrPngBtn.addEventListener('click', () => {
            const link = document.createElement('a');
            link.download = 'encdec_qr.png';
            link.href = el.qrCanvas.toDataURL('image/png');
            link.click();
            showToast("Downloaded QR PNG", "success");
        });

        el.downloadQrSvgBtn.addEventListener('click', async () => {
            const payload = await getQrPayload();
            if (!payload) return;
            const svgStr = QRGenerator.createSvg(payload, 256);
            downloadFile(svgStr, 'encdec_qr.svg', 'image/svg+xml');
            showToast("Downloaded QR SVG", "success");
        });

        el.copyQrImageBtn.addEventListener('click', async () => {
            try {
                el.qrCanvas.toBlob(async (blob) => {
                    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                    showToast("QR Code copied to clipboard", "success");
                });
            } catch (e) {
                showToast("Could not copy QR image directly", "warning");
            }
        });

        el.copyQrPayloadBtn.addEventListener('click', async () => {
            const payload = await getQrPayload();
            copyToClipboard(payload, "QR payload string copied");
        });

        // QR Scanner Camera Controls
        el.startCameraBtn.addEventListener('click', () => {
            if (typeof QRScanner !== 'undefined') {
                QRScanner.startCamera(el.cameraVideo, handleQrScanSuccess);
                el.startCameraBtn.style.display = 'none';
                el.stopCameraBtn.style.display = 'inline-flex';
            }
        });

        el.stopCameraBtn.addEventListener('click', () => {
            if (typeof QRScanner !== 'undefined') {
                QRScanner.stopCamera();
                el.startCameraBtn.style.display = 'inline-flex';
                el.stopCameraBtn.style.display = 'none';
            }
        });

        // QR Image Dropzone & File Input Click
        el.qrImageDropzone.addEventListener('click', () => el.qrImageInput.click());
        el.qrImageInput.addEventListener('change', async (e) => {
            if (e.target.files && e.target.files.length > 0) {
                const file = e.target.files[0];
                await processQrImageFile(file);
                el.qrImageInput.value = '';
            }
        });

        // Drag & Drop on QR Dropzone
        el.qrImageDropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            el.qrImageDropzone.classList.add('dragover');
        });

        el.qrImageDropzone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            el.qrImageDropzone.classList.remove('dragover');
        });

        el.qrImageDropzone.addEventListener('drop', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            el.qrImageDropzone.classList.remove('dragover');
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                const file = e.dataTransfer.files[0];
                await processQrImageFile(file);
            }
        });

        // Global Paste (Ctrl+V) listener for images & QR strings
        window.addEventListener('paste', async (e) => {
            const items = (e.clipboardData || window.clipboardData)?.items;
            let imageBlob = null;

            if (items) {
                for (let i = 0; i < items.length; i++) {
                    if (items[i].type && items[i].type.indexOf('image') !== -1) {
                        imageBlob = items[i].getAsFile();
                        break;
                    }
                }
            }

            if (!imageBlob && e.clipboardData && e.clipboardData.files && e.clipboardData.files.length > 0) {
                for (let i = 0; i < e.clipboardData.files.length; i++) {
                    if (e.clipboardData.files[i].type && e.clipboardData.files[i].type.startsWith('image/')) {
                        imageBlob = e.clipboardData.files[i];
                        break;
                    }
                }
            }

            if (imageBlob) {
                e.preventDefault();
                showToast("Scanning pasted image for QR code...", "info");
                const success = await processQrImageFile(imageBlob);
                if (success) {
                    switchTab('qr');
                }
                return;
            }

            // If pasting text while on the QR tab and not focusing another input
            const activeTab = document.querySelector('.nav-tab.active')?.getAttribute('data-tab');
            const targetTag = e.target ? e.target.tagName : '';
            const isTextEditable = targetTag === 'TEXTAREA' || targetTag === 'INPUT';

            if (activeTab === 'qr' && (!isTextEditable || e.target === el.qrImageDropzone)) {
                const text = e.clipboardData?.getData('text/plain')?.trim();
                if (text && (text.startsWith('ENC5:') || text.startsWith('ENC4:') || text.length > 20)) {
                    e.preventDefault();
                    handleQrScanSuccess(text);
                }
            }
        });

        // Send scan to decrypt box
        el.sendScanToDecryptBtn.addEventListener('click', async () => {
            const raw = el.qrScanResultText.textContent;
            const normalized = await EncDecCrypto.normalizeScannedText(raw);
            el.cipherTextInput.value = normalized;
            updateStats();
            updatePayloadBadge();
            switchTab('text');
            handleDecrypt();
        });
    }

    async function processQrImageFile(file) {
        if (!file) return false;
        if (typeof QRScanner === 'undefined') {
            showToast("QR Scanner module is not loaded", "error");
            return false;
        }

        try {
            const result = await QRScanner.scanImageFile(file);
            if (result) {
                handleQrScanSuccess(result);
                return true;
            } else {
                showToast("No QR code detected in the image", "warning");
                return false;
            }
        } catch (err) {
            showToast(err.message || "No QR code detected in the image", "warning");
            return false;
        }
    }

    async function getQrPayload() {
        const text = el.qrSourceInput.value.trim();
        if (!text) return "";
        if (el.qrZlibCompress.checked) {
            return await EncDecCrypto.compressZlib(text);
        }
        return text;
    }

    async function renderQrCode() {
        const payload = await getQrPayload();
        if (!payload) {
            el.qrPayloadStats.textContent = 'Waiting for payload...';
            const ctx = el.qrCanvas.getContext('2d');
            ctx.clearRect(0, 0, el.qrCanvas.width, el.qrCanvas.height);
            return;
        }

        try {
            QRGenerator.drawToCanvas(payload, el.qrCanvas, {
                size: 220,
                colorDark: '#0f172a',
                colorLight: '#ffffff'
            });
            el.qrPayloadStats.textContent = `Payload: ${payload.length} chars | Zlib: ${el.qrZlibCompress.checked ? 'Active' : 'Off'}`;
        } catch (e) {
            el.qrPayloadStats.textContent = `QR Error: ${e.message}`;
        }
    }

    function handleQrScanSuccess(rawText) {
        showToast("QR Code Scanned!", "success");
        el.qrScanResultCard.style.display = 'flex';
        el.qrScanResultText.textContent = rawText;
        logActivity(`QR Scanned: ${rawText.substring(0, 40)}...`);
    }

    // =========================================================================
    // Security & Key Profiles Table & Benchmarks
    // =========================================================================
    function initSecurityTable() {
        const tbody = el.keyConfigTable.querySelector('tbody');
        tbody.innerHTML = '';

        Object.entries(EncDecCrypto.KEY_CONFIGS).forEach(([key, conf]) => {
            const tr = document.createElement('tr');
            const memMb = Math.round((conf.scryptN * conf.scryptR * 128) / (1024 * 1024));
            const kdfDesc = `Scrypt (${memMb} MB RAM, N=${conf.scryptN.toLocaleString()})`;

            tr.innerHTML = `
                <td><strong style="color: var(--accent-blue);">${conf.alias}</strong></td>
                <td>${kdfDesc}</td>
                <td>${conf.cipher}</td>
                <td><span class="app-badge" style="background: rgba(16,185,129,0.15); color: var(--accent-green);">${conf.securityRating}</span></td>
                <td id="bench-${conf.alias.replace(/\s+/g, '_')}" style="font-family: var(--font-mono); color: var(--text-dim);">-</td>
            `;
            tbody.appendChild(tr);
        });

        el.runBenchmarkBtn.addEventListener('click', runLocalBenchmark);
    }

    async function runLocalBenchmark() {
        el.runBenchmarkBtn.disabled = true;
        el.runBenchmarkBtn.textContent = "⏳ Benchmarking...";
        showToast("Running cryptographic benchmark suite...", "info");

        for (const [key, conf] of Object.entries(EncDecCrypto.KEY_CONFIGS)) {
            const cellId = `bench-${conf.alias.replace(/\s+/g, '_')}`;
            const cell = document.getElementById(cellId);
            if (!cell) continue;

            cell.textContent = "Testing...";
            await new Promise(r => setTimeout(r, 10));

            try {
                const start = performance.now();
                const testPwd = "BenchmarkPassword123!";
                const testSalt = new Uint8Array(conf.saltLength);
                const k = await EncDecCrypto.deriveMasterKey(testPwd, testSalt, conf, null, 32);
                await EncDecCrypto.encryptAesGcm(new TextEncoder().encode("Benchmark payload data"), k);
                const elapsed = Math.round(performance.now() - start);
                cell.textContent = `${elapsed} ms`;
                cell.style.color = elapsed > 500 ? "var(--accent-amber)" : "var(--accent-green)";
            } catch (e) {
                cell.textContent = "Error";
                cell.style.color = "var(--accent-red)";
            }
        }

        el.runBenchmarkBtn.disabled = false;
        el.runBenchmarkBtn.textContent = "⚡ Run Local Benchmark";
        showToast("Benchmark complete!", "success");
    }

    // =========================================================================
    // Password Generator Modal & Diceware
    // =========================================================================
    function initPasswordModal() {
        el.generatePasswordBtn.addEventListener('click', () => {
            generateNewModalPassword();
            el.passGenModal.classList.add('open');
        });

        el.closePassGenModalBtn.addEventListener('click', () => el.passGenModal.classList.remove('open'));
        el.modalRegenPassBtn.addEventListener('click', generateNewModalPassword);

        // Diceware vs Chars Switcher
        el.genModeDicewareBtn.addEventListener('click', () => {
            passGenMode = 'diceware';
            el.genModeDicewareBtn.classList.add('active');
            el.genModeCharsBtn.classList.remove('active');
            el.dicewareOptionsBox.style.display = 'block';
            el.charsOptionsBox.style.display = 'none';
            generateNewModalPassword();
        });

        el.genModeCharsBtn.addEventListener('click', () => {
            passGenMode = 'chars';
            el.genModeCharsBtn.classList.add('active');
            el.genModeDicewareBtn.classList.remove('active');
            el.dicewareOptionsBox.style.display = 'none';
            el.charsOptionsBox.style.display = 'block';
            generateNewModalPassword();
        });

        el.genDicewareCount.addEventListener('input', () => {
            el.genDicewareCountVal.textContent = el.genDicewareCount.value;
            generateNewModalPassword();
        });
        el.genDicewareSep.addEventListener('change', generateNewModalPassword);

        el.genPassLength.addEventListener('input', () => {
            el.genPassLengthVal.textContent = el.genPassLength.value;
            generateNewModalPassword();
        });

        [el.genOptUpper, el.genOptLower, el.genOptNums, el.genOptSpecial].forEach(chk => {
            chk.addEventListener('change', generateNewModalPassword);
        });

        el.applyGeneratedPassBtn.addEventListener('click', () => {
            el.masterPassword.value = el.modalGeneratedPassInput.value;
            el.masterPassword.dispatchEvent(new Event('input'));
            el.passGenModal.classList.remove('open');
            showToast("Applied passphrase to Master Password", "success");
        });
    }

    function generateNewModalPassword() {
        if (passGenMode === 'diceware') {
            const count = parseInt(el.genDicewareCount.value, 10) || 6;
            const sep = el.genDicewareSep.value || '-';
            el.modalGeneratedPassInput.value = EncDecCrypto.generateDicewarePassphrase(count, sep);
        } else {
            const len = parseInt(el.genPassLength.value, 10) || 32;
            const symbols = el.genOptSpecial.checked;
            el.modalGeneratedPassInput.value = EncDecCrypto.generateSecurePassword(len, symbols);
        }
    }

    // =========================================================================
    // Activity Log Modal
    // =========================================================================
    function initLogModal() {
        el.openLogBtn.addEventListener('click', () => {
            renderActivityLogs();
            el.logModal.classList.add('open');
        });
        el.closeLogModalBtn.addEventListener('click', () => el.logModal.classList.remove('open'));
        el.clearLogBtn.addEventListener('click', () => {
            activityLogs = [];
            renderActivityLogs();
            showToast("Logs cleared", "info");
        });
        el.exportLogBtn.addEventListener('click', () => {
            const text = activityLogs.map(l => `[${l.time}] ${l.msg}`).join('\n');
            downloadFile(text, 'encdec_audit_log.txt', 'text/plain');
        });
    }

    function logActivity(msg) {
        const time = new Date().toLocaleTimeString();
        activityLogs.unshift({ time, msg });
        if (activityLogs.length > 200) activityLogs.pop();
    }

    function renderActivityLogs() {
        if (activityLogs.length === 0) {
            el.logContainer.innerHTML = '<div style="color: var(--text-dim);">No activity recorded in this session.</div>';
            return;
        }
        el.logContainer.innerHTML = activityLogs.map(l => `
            <div style="border-bottom: 1px solid var(--border-color); padding-bottom: 4px;">
                <span style="color: var(--accent-blue);">[${l.time}]</span> <span>${escapeHtml(l.msg)}</span>
            </div>
        `).join('');
    }

    // =========================================================================
    // Status & Toast Utilities
    // =========================================================================
    function updateStatus(msg, state = "idle", details = "") {
        el.statusMessage.textContent = msg;
        el.statusDetails.textContent = details;
        setBeacon(state === "idle" ? "idle" : state);
    }

    function setBeacon(state) {
        el.statusBeacon.className = 'beacon-dot';
        if (state === 'success') el.statusBeacon.classList.add('success');
        else if (state === 'error') el.statusBeacon.classList.add('error');
        else if (state === 'processing') el.statusBeacon.classList.add('processing');
    }

    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type === 'success' ? 'success' : type === 'error' ? 'error' : ''}`;
        toast.textContent = message;
        el.toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    async function copyToClipboard(text, successMsg) {
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            showToast(successMsg, "success");
        } catch (e) {
            showToast("Failed to copy to clipboard", "error");
        }
    }

    async function pasteFromClipboard() {
        try {
            return await navigator.clipboard.readText();
        } catch (e) {
            showToast("Please allow clipboard permissions or paste with Ctrl+V", "warning");
            return null;
        }
    }

    function downloadFile(content, fileName, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(url);
    }

    function downloadBinaryFile(uint8Array, fileName, mimeType) {
        const blob = new Blob([uint8Array], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(url);
    }

    function formatBytes(bytes, decimals = 1) {
        if (!+bytes) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // Start App
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
