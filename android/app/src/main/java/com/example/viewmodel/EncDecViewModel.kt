package com.example.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.crypto.CipherFormatDetector
import com.example.crypto.DecryptionResult
import com.example.crypto.DetectedFormat
import com.example.crypto.EntropyResult
import com.example.crypto.FernetCrypto
import com.example.crypto.KeyProfile
import com.example.crypto.PasswordEngine
import com.example.crypto.QrCodeHelper
import com.example.crypto.SteganographyEngine
import com.example.crypto.VaultFileEntry
import com.example.model.AuditLogItem
import com.example.model.LogStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

enum class AppTab(val title: String, val iconName: String) {
    TEXT("Text Crypto", "lock"),
    FILE("File Vault", "folder"),
    QR("QR Studio", "qr_code"),
    PROFILES("Security Tiers", "shield"),
    PASSWORD("Passphrase", "key"),
    AUDIT("Audit Logs", "history"),
    WEB("Web Suite", "public")
}

data class SelectedFileItem(
    val uri: Uri,
    val name: String,
    val size: Long
)

data class EncDecUiState(
    val currentTab: AppTab = AppTab.TEXT,
    val masterPassword: String = "",
    val isPasswordVisible: Boolean = false,
    val entropyResult: EntropyResult = PasswordEngine.calculateEntropy(""),
    val selectedProfile: KeyProfile = KeyProfile.DEFAULT,
    val useEnvelope: Boolean = true,
    val autoSync: Boolean = false,
    // Dual-Factor Keyfile (2FA Hardware Token)
    val keyfileName: String? = null,
    val keyfileBytes: ByteArray? = null,
    val hasKeyfile: Boolean = false,
    // Text Crypto
    val plainText: String = "",
    val cipherText: String = "",
    val isTextProcessing: Boolean = false,
    val textStatusMessage: String = "Ready   AES-256-GCM AEAD & Scrypt Memory-Hard",
    val textStatusType: LogStatus = LogStatus.INFO,
    val detectedCipherFormat: DetectedFormat = DetectedFormat("Plaintext", false),
    // File Vault (Single & Batch)
    val selectedFiles: List<SelectedFileItem> = emptyList(),
    val selectedFileUri: Uri? = null,
    val selectedFileName: String? = null,
    val selectedFileSize: Long = 0,
    val filePasswordOverride: String = "",
    val isFileProcessing: Boolean = false,
    val fileProgress: Float = 0f,
    val fileStatusMessage: String = "Drag or pick files to encrypt with ENC5F (AES-256-GCM & Scrypt)",
    val processedFileBytes: ByteArray? = null,
    val processedFileName: String? = null,
    val processedBatchFiles: List<VaultFileEntry> = emptyList(),
    // QR Studio & Steganography
    val qrPayload: String = "",
    val qrUseZlib: Boolean = true,
    val qrBitmap: Bitmap? = null,
    val scannedPayload: String = "",
    val isCameraScanning: Boolean = false,
    val stegoSourceBitmap: Bitmap? = null,
    val stegoResultBitmap: Bitmap? = null,
    val stegoExtractedText: String = "",
    val isStegoProcessing: Boolean = false,
    val stegoStatus: String = "",
    // Security Profiles & Benchmarks
    val isBenchmarking: Boolean = false,
    val benchmarkResults: Map<String, Long> = emptyMap(),
    // Password & Diceware Passphrase Generator
    val isDicewareMode: Boolean = false,
    val dicewareWordCount: Int = 6,
    val dicewareSeparator: String = "-",
    val passGenLength: Int = 32,
    val passGenUpper: Boolean = true,
    val passGenLower: Boolean = true,
    val passGenNumbers: Boolean = true,
    val passGenSymbols: Boolean = true,
    val passGenExcludeAmbiguous: Boolean = true,
    val generatedPassword: String = "",
    val generatedEntropy: EntropyResult = PasswordEngine.calculateEntropy(""),
    // Audit Log
    val auditLogs: List<AuditLogItem> = emptyList()
)

class EncDecViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(EncDecUiState())
    val uiState: StateFlow<EncDecUiState> = _uiState.asStateFlow()

    private val _toastEvents = MutableSharedFlow<String>()
    val toastEvents: SharedFlow<String> = _toastEvents.asSharedFlow()

    private var autoSyncJob: Job? = null
    private var activeCryptoJob: Job? = null

    init {
        regeneratePassword()
        warmupBenchmarksInBackground()
    }

    private fun warmupBenchmarksInBackground() {
        viewModelScope.launch(Dispatchers.Default) {
            val results = mutableMapOf<String, Long>()
            val testPassword = "BenchmarkWarmupPass123!"
            val warmupList = KeyProfile.ALL_PROFILES.take(3)
            for (profile in warmupList) {
                val salt = ByteArray(profile.saltLength) { 0x33.toByte() }
                val t0 = System.currentTimeMillis()
                FernetCrypto.deriveKey(testPassword, salt, profile)
                val duration = System.currentTimeMillis() - t0
                results[profile.alias] = duration
            }
            _uiState.update { it.copy(benchmarkResults = results.toMap()) }
        }
    }

    fun setTab(tab: AppTab) {
        _uiState.update { it.copy(currentTab = tab) }
    }

    fun setMasterPassword(pwd: String) {
        val entropy = PasswordEngine.calculateEntropy(pwd)
        _uiState.update { 
            it.copy(
                masterPassword = pwd,
                entropyResult = entropy
            )
        }
        if (_uiState.value.autoSync && pwd.isNotEmpty() && _uiState.value.plainText.isNotEmpty()) {
            triggerAutoSync()
        }
    }

    fun togglePasswordVisibility() {
        _uiState.update { it.copy(isPasswordVisible = !it.isPasswordVisible) }
    }

    fun setSelectedProfile(profile: KeyProfile) {
        _uiState.update { it.copy(selectedProfile = profile) }
        if (_uiState.value.autoSync && _uiState.value.plainText.isNotEmpty()) {
            triggerAutoSync()
        }
    }

    fun setKeyfile(uri: Uri, name: String, bytes: ByteArray) {
        _uiState.update {
            it.copy(
                keyfileName = name,
                keyfileBytes = bytes,
                hasKeyfile = true
            )
        }
        addAuditLog("Attach Keyfile", "2FA Token", LogStatus.SUCCESS, "Keyfile attached: $name (${bytes.size}B)")
        showToast("2FA Keyfile attached: $name")
        if (_uiState.value.autoSync && _uiState.value.plainText.isNotEmpty()) {
            triggerAutoSync()
        }
    }

    fun removeKeyfile() {
        _uiState.update {
            it.copy(
                keyfileName = null,
                keyfileBytes = null,
                hasKeyfile = false
            )
        }
        addAuditLog("Remove Keyfile", "2FA Token", LogStatus.INFO, "Keyfile detached")
        showToast("Keyfile removed")
        if (_uiState.value.autoSync && _uiState.value.plainText.isNotEmpty()) {
            triggerAutoSync()
        }
    }

    fun setAutoSync(enabled: Boolean) {
        _uiState.update { it.copy(autoSync = enabled) }
        if (enabled) {
            triggerAutoSync()
        }
    }

    fun setUseEnvelope(enabled: Boolean) {
        _uiState.update { it.copy(useEnvelope = enabled) }
    }

    fun setPlainText(text: String) {
        _uiState.update { it.copy(plainText = text) }
        if (_uiState.value.autoSync && text.isNotEmpty()) {
            triggerAutoSync()
        }
    }

    fun setCipherText(text: String) {
        val analysis = CipherFormatDetector.analyze(text)
        _uiState.update {
            it.copy(
                cipherText = text,
                detectedCipherFormat = analysis,
                selectedProfile = analysis.suggestedProfile ?: it.selectedProfile
            )
        }
    }

    private fun triggerAutoSync() {
        autoSyncJob?.cancel()
        autoSyncJob = viewModelScope.launch {
            delay(400)
            encryptText(isAutoSync = true)
        }
    }

    fun cancelActiveOperation() {
        activeCryptoJob?.cancel(CancellationException("User cancelled operation"))
        _uiState.update {
            it.copy(
                isTextProcessing = false,
                isFileProcessing = false,
                isStegoProcessing = false,
                fileProgress = 0f,
                fileStatusMessage = "Operation cancelled"
            )
        }
        showToast("Operation cancelled")
    }

    fun encryptText(isAutoSync: Boolean = false) {
        val state = _uiState.value
        if (state.masterPassword.isEmpty()) {
            if (!isAutoSync) showToast("Please set a Master Password")
            return
        }
        if (state.plainText.isEmpty()) {
            if (!isAutoSync) showToast("Plaintext is empty")
            return
        }
        activeCryptoJob?.cancel()
        activeCryptoJob = viewModelScope.launch {
            _uiState.update { it.copy(isTextProcessing = true) }
            val startTime = System.currentTimeMillis()
            try {
                val encrypted = withContext(Dispatchers.Default) {
                    FernetCrypto.encryptText(
                        plainText = state.plainText,
                        password = state.masterPassword,
                        profile = state.selectedProfile,
                        keyfileBytes = state.keyfileBytes,
                        useEnvelope = state.useEnvelope
                    )
                }
                val duration = System.currentTimeMillis() - startTime
                val analysis = CipherFormatDetector.analyze(encrypted)
                val keyfileNote = if (state.hasKeyfile) " + 2FA Keyfile" else ""
                _uiState.update {
                    it.copy(
                        cipherText = encrypted,
                        isTextProcessing = false,
                        detectedCipherFormat = analysis,
                        textStatusMessage = "  Encrypted with ${state.selectedProfile.alias} (${state.selectedProfile.memoryMb}MB RAM   ${duration}ms$keyfileNote)",
                        textStatusType = LogStatus.SUCCESS
                    )
                }
                addAuditLog("Encrypt Text (AES-256)", state.selectedProfile.alias, LogStatus.SUCCESS, "Encrypted ${state.plainText.length} chars in ${duration}ms$keyfileNote")
                if (!isAutoSync) showToast("Encrypted with AES-256-GCM (ENC5)!")
            } catch (e: Exception) {
                if (e is CancellationException) return@launch
                _uiState.update {
                    it.copy(
                        isTextProcessing = false,
                        textStatusMessage = "Encryption error: ${e.message}",
                        textStatusType = LogStatus.FAILED
                    )
                }
                addAuditLog("Encrypt Text", state.selectedProfile.alias, LogStatus.FAILED, "Error: ${e.message}")
            }
        }
    }

    fun decryptText() {
        val state = _uiState.value
        if (state.masterPassword.isEmpty()) {
            showToast("Please enter Master Password")
            return
        }
        if (state.cipherText.isBlank()) {
            showToast("Ciphertext is empty")
            return
        }
        activeCryptoJob?.cancel()
        activeCryptoJob = viewModelScope.launch {
            _uiState.update { it.copy(isTextProcessing = true) }
            val startTime = System.currentTimeMillis()
            try {
                val result: DecryptionResult = withContext(Dispatchers.Default) {
                    FernetCrypto.decryptText(
                        cipherInput = state.cipherText,
                        password = state.masterPassword,
                        selectedProfile = state.selectedProfile,
                        keyfileBytes = state.keyfileBytes
                    )
                }
                val duration = System.currentTimeMillis() - startTime
                _uiState.update {
                    it.copy(
                        plainText = result.decryptedText,
                        isTextProcessing = false,
                        selectedProfile = result.keyProfile,
                        textStatusMessage = "  Decrypted with ${result.keyProfile.alias} [${result.cipherEngine}] (${duration}ms)",
                        textStatusType = LogStatus.SUCCESS
                    )
                }
                addAuditLog("Decrypt Text", result.keyProfile.alias, LogStatus.SUCCESS, "Decrypted ${result.decryptedText.length} chars in ${duration}ms [${result.cipherEngine}]")
                showToast("Decrypted successfully!")
            } catch (e: Exception) {
                if (e is CancellationException) return@launch
                _uiState.update {
                    it.copy(
                        isTextProcessing = false,
                        textStatusMessage = "Decryption failed: ${e.message}",
                        textStatusType = LogStatus.FAILED
                    )
                }
                addAuditLog("Decrypt Text", state.selectedProfile.alias, LogStatus.FAILED, "Error: ${e.message}")
                showToast("Decryption failed. Check password and 2FA keyfile.")
            }
        }
    }

    fun selectMultipleFiles(items: List<SelectedFileItem>) {
        if (items.isEmpty()) return
        val totalSize = items.sumOf { it.size }
        _uiState.update {
            it.copy(
                selectedFiles = items,
                selectedFileUri = items.firstOrNull()?.uri,
                selectedFileName = if (items.size == 1) items.first().name else "${items.size} files (${totalSize / 1024} KB)",
                selectedFileSize = totalSize,
                fileStatusMessage = "Selected ${items.size} file(s)   Ready for ENC5F AES-256 Vault",
                processedFileBytes = null,
                processedFileName = null,
                processedBatchFiles = emptyList(),
                fileProgress = 0f
            )
        }
    }

    fun selectFile(uri: Uri, name: String, size: Long) {
        val item = SelectedFileItem(uri, name, size)
        selectMultipleFiles(listOf(item))
    }

    fun setFilePasswordOverride(pwd: String) {
        _uiState.update { it.copy(filePasswordOverride = pwd) }
    }

    fun copyMasterPasswordToFile() {
        _uiState.update { it.copy(filePasswordOverride = it.masterPassword) }
        showToast("Master Password copied to File Vault")
    }

    fun encryptSelectedFiles(context: Context) {
        val state = _uiState.value
        if (state.selectedFiles.isEmpty()) {
            showToast("No files selected")
            return
        }
        val pwd = if (state.filePasswordOverride.isNotEmpty()) state.filePasswordOverride else state.masterPassword
        if (pwd.isEmpty()) {
            showToast("Please provide password for file encryption")
            return
        }
        activeCryptoJob?.cancel()
        activeCryptoJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isFileProcessing = true,
                    fileProgress = 0.05f,
                    fileStatusMessage = "Encrypting with ENC5F (AES-256-GCM & ${state.selectedProfile.memoryMb}MB Scrypt)..."
                )
            }
            val startTime = System.currentTimeMillis()
            try {
                val processedResult = withContext(Dispatchers.IO) {
                    if (state.selectedFiles.size == 1) {
                        val fileItem = state.selectedFiles[0]
                        val inputStream = context.contentResolver.openInputStream(fileItem.uri)
                            ?: throw IllegalStateException("Cannot open input file")
                        val tempOut = File(context.cacheDir, "temp_encrypted.enc")
                        FileOutputStream(tempOut).use { fos ->
                            FernetCrypto.encryptFileStream(
                                inputStream = inputStream,
                                outputStream = fos,
                                password = pwd,
                                profile = state.selectedProfile,
                                keyfileBytes = state.keyfileBytes,
                                origName = fileItem.name,
                                totalBytes = fileItem.size,
                                onProgress = { p -> _uiState.update { it.copy(fileProgress = p) } }
                            )
                        }
                        inputStream.close()
                        val bytes = tempOut.readBytes()
                        tempOut.delete()
                        val outName = "${fileItem.name}.enc"
                        Pair(bytes, outName)
                    } else {
                        val entries = state.selectedFiles.mapNotNull { item ->
                            val bytes = context.contentResolver.openInputStream(item.uri)?.use { it.readBytes() }
                            bytes?.let { VaultFileEntry(item.name, item.size, it) }
                        }
                        val zipBytes = FernetCrypto.createZipArchive(entries)
                        val encBytes = FernetCrypto.encryptFile(
                            fileBytes = zipBytes,
                            password = pwd,
                            profile = state.selectedProfile,
                            keyfileBytes = state.keyfileBytes,
                            origName = "Vault_Archive_${state.selectedFiles.size}_files.zip"
                        )
                        val outName = "Vault_Archive_${state.selectedFiles.size}_files.enc"
                        Pair(encBytes, outName)
                    }
                }
                val duration = System.currentTimeMillis() - startTime
                _uiState.update {
                    it.copy(
                        isFileProcessing = false,
                        fileProgress = 1.0f,
                        processedFileBytes = processedResult.first,
                        processedFileName = processedResult.second,
                        fileStatusMessage = "  ENC5F Created: ${processedResult.second} (${duration}ms   ${state.selectedProfile.memoryMb}MB RAM)"
                    )
                }
                addAuditLog("Encrypt File(s) [ENC5F]", state.selectedProfile.alias, LogStatus.SUCCESS, "Encrypted ${processedResult.second} (${processedResult.first.size}B)")
                showToast("ENC5F Vault container created successfully!")
            } catch (e: Exception) {
                if (e is CancellationException) return@launch
                _uiState.update {
                    it.copy(
                        isFileProcessing = false,
                        fileProgress = 0f,
                        fileStatusMessage = "File encryption failed: ${e.message}"
                    )
                }
                addAuditLog("Encrypt File", state.selectedProfile.alias, LogStatus.FAILED, "Error: ${e.message}")
            }
        }
    }

    fun decryptSelectedFiles(context: Context) {
        val state = _uiState.value
        if (state.selectedFiles.isEmpty()) {
            showToast("No files selected")
            return
        }
        val pwd = if (state.filePasswordOverride.isNotEmpty()) state.filePasswordOverride else state.masterPassword
        if (pwd.isEmpty()) {
            showToast("Please provide password for file decryption")
            return
        }
        activeCryptoJob?.cancel()
        activeCryptoJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isFileProcessing = true,
                    fileProgress = 0.05f,
                    fileStatusMessage = "Decrypting container stream..."
                )
            }
            val startTime = System.currentTimeMillis()
            try {
                val fileItem = state.selectedFiles.first()
                val (decryptedBytes, usedProfile, extractedBatch) = withContext(Dispatchers.IO) {
                    val input = context.contentResolver.openInputStream(fileItem.uri)
                        ?: throw IllegalStateException("Cannot read file")
                    val tempOut = File(context.cacheDir, "temp_decrypted.bin")
                    val profile = FileOutputStream(tempOut).use { fos ->
                        FernetCrypto.decryptFileStream(
                            inputStream = input,
                            outputStream = fos,
                            password = pwd,
                            keyfileBytes = state.keyfileBytes,
                            totalBytes = fileItem.size,
                            onProgress = { p -> _uiState.update { it.copy(fileProgress = p) } }
                        )
                    }
                    input.close()
                    val bytes = tempOut.readBytes()
                    tempOut.delete()
                    var batchEntries: List<VaultFileEntry> = emptyList()
                    try {
                        val unzipped = FernetCrypto.extractZipArchive(bytes)
                        if (unzipped.isNotEmpty()) {
                            batchEntries = unzipped
                        }
                    } catch (_: Exception) {}
                    Triple(bytes, profile, batchEntries)
                }
                val duration = System.currentTimeMillis() - startTime
                val originalName = fileItem.name.removeSuffix(".enc")
                _uiState.update {
                    it.copy(
                        isFileProcessing = false,
                        fileProgress = 1.0f,
                        processedFileBytes = decryptedBytes,
                        processedFileName = originalName,
                        processedBatchFiles = extractedBatch,
                        selectedProfile = usedProfile,
                        fileStatusMessage = if (extractedBatch.isNotEmpty()) {
                            "  Unpacked vault archive: ${extractedBatch.size} files (${duration}ms)"
                        } else {
                            "  Decrypted: $originalName (${duration}ms   ${usedProfile.alias})"
                        }
                    )
                }
                addAuditLog("Decrypt File", usedProfile.alias, LogStatus.SUCCESS, "Decrypted ${fileItem.name} (${decryptedBytes.size}B)")
                showToast("File decrypted successfully!")
            } catch (e: Exception) {
                if (e is CancellationException) return@launch
                _uiState.update {
                    it.copy(
                        isFileProcessing = false,
                        fileProgress = 0f,
                        fileStatusMessage = "Decryption failed: ${e.message}"
                    )
                }
                addAuditLog("Decrypt File", state.selectedProfile.alias, LogStatus.FAILED, "Error: ${e.message}")
                showToast("Decryption failed. Invalid password, keyfile, or container.")
            }
        }
    }

    fun shareText(context: Context, text: String, title: String = "Share Crypto Content") {
        if (text.isBlank()) {
            showToast("Nothing to share")
            return
        }
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val shareIntent = Intent.createChooser(sendIntent, title).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        context.startActivity(shareIntent)
    }

    fun shareProcessedFile(context: Context) {
        val state = _uiState.value
        val bytes = state.processedFileBytes ?: run {
            showToast("No processed file to share")
            return
        }
        val filename = state.processedFileName ?: "encdec_file.bin"
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val shareDir = File(context.cacheDir, "shared_vault").apply { mkdirs() }
                val file = File(shareDir, filename).apply { writeBytes(bytes) }
                val uri = FileProvider.getUriForFile(
                    context,
                    "${context.packageName}.fileprovider",
                    file
                )
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "*/*"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK
                }
                val chooser = Intent.createChooser(intent, "Share $filename").apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(chooser)
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showToast("Share failed: ${e.message}")
                }
            }
        }
    }

    fun handleIncomingIntent(intent: Intent?, context: Context) {
        if (intent == null) return
        val action = intent.action
        val type = intent.type ?: return
        when (action) {
            Intent.ACTION_SEND -> {
                if (type.startsWith("text/")) {
                    val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    if (!sharedText.isNullOrBlank()) {
                        val analysis = CipherFormatDetector.analyze(sharedText)
                        if (analysis.isEncrypted) {
                            setCipherText(sharedText)
                            _uiState.update { it.copy(currentTab = AppTab.TEXT) }
                            showToast("Ciphertext received from Share Sheet")
                        } else {
                            setPlainText(sharedText)
                            _uiState.update { it.copy(currentTab = AppTab.TEXT) }
                            showToast("Plaintext received from Share Sheet")
                        }
                    }
                } else {
                    val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                    uri?.let {
                        val (name, size) = queryFileInfo(context, it)
                        selectFile(it, name, size)
                        _uiState.update { it.copy(currentTab = AppTab.FILE) }
                        showToast("File received: $name")
                    }
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
                if (!uris.isNullOrEmpty()) {
                    val items = uris.map { uri ->
                        val (name, size) = queryFileInfo(context, uri)
                        SelectedFileItem(uri, name, size)
                    }
                    selectMultipleFiles(items)
                    _uiState.update { it.copy(currentTab = AppTab.FILE) }
                    showToast("${items.size} files received from Share Sheet")
                }
            }
        }
    }

    private fun queryFileInfo(context: Context, uri: Uri): Pair<String, Long> {
        var name = "shared_file"
        var size = 0L
        try {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIdx != -1) name = cursor.getString(nameIdx) ?: "shared_file"
                    if (sizeIdx != -1) size = cursor.getLong(sizeIdx)
                }
            }
        } catch (_: Exception) {}
        return Pair(name, size)
    }

    fun setStegoSourceBitmap(bitmap: Bitmap) {
        _uiState.update {
            it.copy(
                stegoSourceBitmap = bitmap,
                stegoResultBitmap = null,
                stegoExtractedText = "",
                stegoStatus = "Image loaded (${bitmap.width}x${bitmap.height}   Capacity: ${SteganographyEngine.calculateCapacity(bitmap.width, bitmap.height)} bytes)"
            )
        }
    }

    fun embedStegoPayload(payload: String) {
        val bitmap = _uiState.value.stegoSourceBitmap ?: run {
            showToast("Please pick a carrier image first")
            return
        }
        val textToHide = payload.ifEmpty { _uiState.value.cipherText }
        if (textToHide.isBlank()) {
            showToast("No ciphertext or payload to hide")
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(isStegoProcessing = true, stegoStatus = "Embedding data into image...") }
            try {
                val stegoBitmap = withContext(Dispatchers.Default) {
                    SteganographyEngine.embedPayload(bitmap, textToHide)
                }
                _uiState.update {
                    it.copy(
                        isStegoProcessing = false,
                        stegoResultBitmap = stegoBitmap,
                        stegoStatus = "  Steganography successful! Data embedded into pixels."
                    )
                }
                addAuditLog("Steganography Embed", "LSB", LogStatus.SUCCESS, "Embedded ${textToHide.length} chars into image")
                showToast("Hidden in image successfully!")
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isStegoProcessing = false,
                        stegoStatus = "Embedding error: ${e.message}"
                    )
                }
                showToast("Stego error: ${e.message}")
            }
        }
    }

    fun extractStegoPayload() {
        val bitmap = _uiState.value.stegoSourceBitmap ?: run {
            showToast("Please pick an image to extract from")
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(isStegoProcessing = true, stegoStatus = "Scanning image pixels for hidden data...") }
            try {
                val extracted = withContext(Dispatchers.Default) {
                    SteganographyEngine.extractPayload(bitmap)
                }
                if (extracted != null) {
                    val analysis = CipherFormatDetector.analyze(extracted)
                    _uiState.update {
                        it.copy(
                            isStegoProcessing = false,
                            stegoExtractedText = extracted,
                            cipherText = extracted,
                            detectedCipherFormat = analysis,
                            stegoStatus = "  Hidden payload discovered! (${extracted.length} bytes)"
                        )
                    }
                    addAuditLog("Steganography Extract", "LSB", LogStatus.SUCCESS, "Extracted ${extracted.length} chars from image")
                    showToast("Hidden payload extracted!")
                } else {
                    _uiState.update {
                        it.copy(
                            isStegoProcessing = false,
                            stegoStatus = "No hidden EncDec payload found in this image"
                        )
                    }
                    showToast("No hidden payload found")
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isStegoProcessing = false,
                        stegoStatus = "Extraction error: ${e.message}"
                    )
                }
            }
        }
    }

    fun setQrPayload(text: String) {
        _uiState.update { it.copy(qrPayload = text) }
        generateQrCode(text, _uiState.value.qrUseZlib)
    }

    fun setQrUseZlib(useZlib: Boolean) {
        _uiState.update { it.copy(qrUseZlib = useZlib) }
        generateQrCode(_uiState.value.qrPayload, useZlib)
    }

    fun transferCipherToQr() {
        val cipher = _uiState.value.cipherText
        if (cipher.isBlank()) {
            showToast("Ciphertext is empty")
            return
        }
        _uiState.update { it.copy(qrPayload = cipher, currentTab = AppTab.QR) }
        generateQrCode(cipher, _uiState.value.qrUseZlib)
        showToast("Ciphertext transferred to QR Studio")
    }

    fun transferScannedToDecrypt() {
        val scanned = _uiState.value.scannedPayload
        if (scanned.isBlank()) {
            showToast("No scanned QR payload")
            return
        }
        val analysis = CipherFormatDetector.analyze(scanned)
        _uiState.update {
            it.copy(
                cipherText = scanned,
                detectedCipherFormat = analysis,
                selectedProfile = analysis.suggestedProfile ?: it.selectedProfile,
                currentTab = AppTab.TEXT
            )
        }
        showToast("Transferred to Decrypt box")
    }

    private fun generateQrCode(payload: String, useZlib: Boolean) {
        if (payload.isBlank()) {
            _uiState.update { it.copy(qrBitmap = null) }
            return
        }
        viewModelScope.launch {
            val finalContent = withContext(Dispatchers.Default) {
                if (useZlib) {
                    try {
                        val compressed = FernetCrypto.compressZlib(payload.toByteArray(Charsets.UTF_8))
                        FernetCrypto.b64UrlEncode(compressed)
                    } catch (_: Exception) {
                        payload
                    }
                } else {
                    payload
                }
            }
            val bitmap = withContext(Dispatchers.Default) {
                QrCodeHelper.generateQrBitmap(finalContent, 600, 0xFF0F172A.toInt(), 0xFFFFFFFF.toInt())
            }
            _uiState.update { it.copy(qrBitmap = bitmap) }
        }
    }

    fun setScannedPayload(rawText: String) {
        val normalized = FernetCrypto.normalizeQrPayload(rawText)
        _uiState.update { it.copy(scannedPayload = normalized) }
        addAuditLog("Scan QR", "N/A", LogStatus.SUCCESS, "Scanned payload: ${normalized.take(30)}...")
        showToast("QR Code recognized!")
    }

    fun setCameraScanning(scanning: Boolean) {
        _uiState.update { it.copy(isCameraScanning = scanning) }
    }

    fun decodeQrFromImage(bitmap: Bitmap) {
        val decoded = QrCodeHelper.decodeQrBitmap(bitmap)
        if (decoded != null) {
            setScannedPayload(decoded)
        } else {
            showToast("No valid QR code found in image")
        }
    }

    fun runLocalBenchmark() {
        if (_uiState.value.isBenchmarking) return
        viewModelScope.launch {
            _uiState.update { it.copy(isBenchmarking = true) }
            val results = mutableMapOf<String, Long>()
            val testPassword = "BenchmarkTestSecretPassword123!"
            withContext(Dispatchers.Default) {
                for (profile in KeyProfile.ALL_PROFILES) {
                    val salt = ByteArray(profile.saltLength) { 0x42.toByte() }
                    val t0 = System.currentTimeMillis()
                    FernetCrypto.deriveKey(testPassword, salt, profile)
                    val duration = System.currentTimeMillis() - t0
                    results[profile.alias] = duration
                    _uiState.update { it.copy(benchmarkResults = results.toMap()) }
                }
            }
            _uiState.update { it.copy(isBenchmarking = false, benchmarkResults = results) }
            addAuditLog("Run Benchmark", "Memory-Hard Scrypt", LogStatus.SUCCESS, "Benchmarked 10 GPU-proof memory profiles")
            showToast("Benchmark completed!")
        }
    }

    fun setDicewareMode(enabled: Boolean) {
        _uiState.update { it.copy(isDicewareMode = enabled) }
        regeneratePassword()
    }

    fun setDicewareWordCount(count: Int) {
        _uiState.update { it.copy(dicewareWordCount = count) }
        regeneratePassword()
    }

    fun setDicewareSeparator(sep: String) {
        _uiState.update { it.copy(dicewareSeparator = sep) }
        regeneratePassword()
    }

    fun setPassGenConfig(
        length: Int = _uiState.value.passGenLength,
        upper: Boolean = _uiState.value.passGenUpper,
        lower: Boolean = _uiState.value.passGenLower,
        num: Boolean = _uiState.value.passGenNumbers,
        sym: Boolean = _uiState.value.passGenSymbols,
        excludeAmbiguous: Boolean = _uiState.value.passGenExcludeAmbiguous
    ) {
        _uiState.update {
            it.copy(
                passGenLength = length,
                passGenUpper = upper,
                passGenLower = lower,
                passGenNumbers = num,
                passGenSymbols = sym,
                passGenExcludeAmbiguous = excludeAmbiguous
            )
        }
        regeneratePassword()
    }

    fun regeneratePassword() {
        val state = _uiState.value
        val pass = if (state.isDicewareMode) {
            PasswordEngine.generateDiceware(
                wordCount = state.dicewareWordCount,
                separator = state.dicewareSeparator
            )
        } else {
            PasswordEngine.generatePassword(
                length = state.passGenLength,
                includeUpper = state.passGenUpper,
                includeLower = state.passGenLower,
                includeNumbers = state.passGenNumbers,
                includeSymbols = state.passGenSymbols,
                excludeAmbiguous = state.passGenExcludeAmbiguous
            )
        }
        val entropy = PasswordEngine.calculateEntropy(pass)
        _uiState.update {
            it.copy(
                generatedPassword = pass,
                generatedEntropy = entropy
            )
        }
    }

    fun applyGeneratedPasswordToMaster() {
        setMasterPassword(_uiState.value.generatedPassword)
        showToast("Applied to Master Password!")
    }

    private fun addAuditLog(action: String, keyTier: String, status: LogStatus, details: String) {
        val item = AuditLogItem(
            action = action,
            keyTier = keyTier,
            status = status,
            details = details
        )
        _uiState.update { it.copy(auditLogs = listOf(item) + it.auditLogs.take(99)) }
    }

    fun clearAuditLogs() {
        _uiState.update { it.copy(auditLogs = emptyList()) }
        showToast("Audit logs cleared")
    }

    fun getAuditLogsExportText(): String {
        val sb = StringBuilder("=== EncDec Studio Pro (v5.0) Audit Log ===\nGenerated: ${System.currentTimeMillis()}\nEngine: AES-256-GCM AEAD & Scrypt (Memory-Hard)\n\n")
        _uiState.value.auditLogs.forEach { log ->
            sb.append("[${log.formattedDateTime}] [${log.status}] ${log.action} (${log.keyTier}) - ${log.details}\n")
        }
        return sb.toString()
    }

    private fun showToast(message: String) {
        viewModelScope.launch {
            _toastEvents.emit(message)
        }
    }
}
