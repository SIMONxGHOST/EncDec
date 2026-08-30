package com.example

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.components.EncDecHeader
import com.example.ui.components.MasterPasswordBar
import com.example.ui.screens.AuditLogScreen
import com.example.ui.screens.FileVaultScreen
import com.example.ui.screens.PasswordGeneratorScreen
import com.example.ui.screens.QrStudioScreen
import com.example.ui.screens.SecurityProfilesScreen
import com.example.ui.screens.TextCryptoScreen
import com.example.ui.screens.WebSuiteScreen
import com.example.ui.theme.MyApplicationTheme
import com.example.viewmodel.AppTab
import com.example.viewmodel.EncDecViewModel
import kotlinx.coroutines.flow.collectLatest

class MainActivity : ComponentActivity() {

    private val viewModel: EncDecViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        viewModel.handleIncomingIntent(intent, this)

        setContent {
            val systemDark = isSystemInDarkTheme()
            var isDarkTheme by remember { mutableStateOf(systemDark) }

            MyApplicationTheme(darkTheme = isDarkTheme) {
                val uiState by viewModel.uiState.collectAsState()
                val context = LocalContext.current
                val snackbarHostState = remember { SnackbarHostState() }

                LaunchedEffect(Unit) {
                    viewModel.toastEvents.collectLatest { msg ->
                        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                    }
                }

                Scaffold(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MaterialTheme.colorScheme.background)
                        .statusBarsPadding()
                        .navigationBarsPadding(),
                    topBar = {
                        EncDecHeader(
                            isDarkTheme = isDarkTheme,
                            onToggleTheme = { isDarkTheme = !isDarkTheme }
                        )
                    },
                    bottomBar = {
                        EncDecBottomBar(
                            currentTab = uiState.currentTab,
                            onTabSelected = { viewModel.setTab(it) }
                        )
                    },
                    snackbarHost = { SnackbarHost(snackbarHostState) }
                ) { innerPadding ->
                    val masterPasswordBarContent: @Composable () -> Unit = {
                        MasterPasswordBar(
                            password = uiState.masterPassword,
                            onPasswordChange = { viewModel.setMasterPassword(it) },
                            isPasswordVisible = uiState.isPasswordVisible,
                            onToggleVisibility = { viewModel.togglePasswordVisibility() },
                            entropyResult = uiState.entropyResult,
                            selectedProfile = uiState.selectedProfile,
                            onProfileSelected = { viewModel.setSelectedProfile(it) },
                            autoSync = uiState.autoSync,
                            onToggleAutoSync = { viewModel.setAutoSync(it) },
                            keyfileName = uiState.keyfileName,
                            hasKeyfile = uiState.hasKeyfile,
                            onAttachKeyfile = { uri, name, bytes -> viewModel.setKeyfile(uri, name, bytes) },
                            onRemoveKeyfile = { viewModel.removeKeyfile() },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                    ) {
                        AnimatedContent(
                            targetState = uiState.currentTab,
                            transitionSpec = { fadeIn() togetherWith fadeOut() },
                            label = "tabContent",
                            modifier = Modifier.fillMaxSize()
                        ) { tab ->
                            when (tab) {
                                AppTab.TEXT -> TextCryptoScreen(
                                    state = uiState,
                                    headerContent = masterPasswordBarContent,
                                    onPlainTextChange = { viewModel.setPlainText(it) },
                                    onCipherTextChange = { viewModel.setCipherText(it) },
                                    onUseEnvelopeChange = { viewModel.setUseEnvelope(it) },
                                    onEncrypt = { viewModel.encryptText() },
                                    onDecrypt = { viewModel.decryptText() },
                                    onTransferToQr = { viewModel.transferCipherToQr() }
                                )
                                AppTab.FILE -> FileVaultScreen(
                                    state = uiState,
                                    headerContent = masterPasswordBarContent,
                                    onFilesSelected = { items -> viewModel.selectMultipleFiles(items) },
                                    onFilePasswordChange = { viewModel.setFilePasswordOverride(it) },
                                    onCopyMasterPassword = { viewModel.copyMasterPasswordToFile() },
                                    onEncryptFiles = { viewModel.encryptSelectedFiles(context) },
                                    onDecryptFiles = { viewModel.decryptSelectedFiles(context) },
                                    onCancelOperation = { viewModel.cancelActiveOperation() },
                                    onShareFile = { viewModel.shareProcessedFile(context) }
                                )
                                AppTab.QR -> QrStudioScreen(
                                    state = uiState,
                                    headerContent = masterPasswordBarContent,
                                    onQrPayloadChange = { viewModel.setQrPayload(it) },
                                    onToggleZlib = { viewModel.setQrUseZlib(it) },
                                    onScannedResult = { viewModel.setScannedPayload(it) },
                                    onDecodeImageBitmap = { viewModel.decodeQrFromImage(it) },
                                    onTransferScannedToDecrypt = { viewModel.transferScannedToDecrypt() },
                                    onSetStegoSourceBitmap = { viewModel.setStegoSourceBitmap(it) },
                                    onEmbedStego = { viewModel.embedStegoPayload(it) },
                                    onExtractStego = { viewModel.extractStegoPayload() }
                                )
                                AppTab.PROFILES -> SecurityProfilesScreen(
                                    state = uiState,
                                    onRunBenchmark = { viewModel.runLocalBenchmark() },
                                    onSelectProfile = { viewModel.setSelectedProfile(it) }
                                )
                                AppTab.PASSWORD -> PasswordGeneratorScreen(
                                    state = uiState,
                                    onLengthChange = { viewModel.setPassGenConfig(length = it) },
                                    onToggleUpper = { viewModel.setPassGenConfig(upper = it) },
                                    onToggleLower = { viewModel.setPassGenConfig(lower = it) },
                                    onToggleNumbers = { viewModel.setPassGenConfig(num = it) },
                                    onToggleSymbols = { viewModel.setPassGenConfig(sym = it) },
                                    onToggleExcludeAmbiguous = { viewModel.setPassGenConfig(excludeAmbiguous = it) },
                                    onToggleDicewareMode = { viewModel.setDicewareMode(it) },
                                    onDicewareWordCountChange = { viewModel.setDicewareWordCount(it) },
                                    onDicewareSeparatorChange = { viewModel.setDicewareSeparator(it) },
                                    onRegenerate = { viewModel.regeneratePassword() },
                                    onApplyToMaster = { viewModel.applyGeneratedPasswordToMaster() }
                                )
                                AppTab.AUDIT -> AuditLogScreen(
                                    state = uiState,
                                    onClearLogs = { viewModel.clearAuditLogs() },
                                    onExportLogsText = { viewModel.getAuditLogsExportText() }
                                )
                                AppTab.WEB -> WebSuiteScreen()
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        viewModel.handleIncomingIntent(intent, this)
    }
}

@Composable
fun EncDecBottomBar(
    currentTab: AppTab,
    onTabSelected: (AppTab) -> Unit,
    modifier: Modifier = Modifier
) {
    ScrollableTabRow(
        selectedTabIndex = currentTab.ordinal,
        modifier = modifier.fillMaxWidth(),
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.primary,
        edgePadding = 8.dp
    ) {
        AppTab.values().forEach { tab ->
            val isSelected = currentTab == tab
            val icon = when (tab) {
                AppTab.TEXT -> Icons.Default.Lock
                AppTab.FILE -> Icons.Default.FolderZip
                AppTab.QR -> Icons.Default.QrCode
                AppTab.PROFILES -> Icons.Default.Shield
                AppTab.PASSWORD -> Icons.Default.Key
                AppTab.AUDIT -> Icons.Default.History
                AppTab.WEB -> Icons.Default.Public
            }
            Tab(
                selected = isSelected,
                onClick = { onTabSelected(tab) },
                text = {
                    Text(
                        text = tab.title,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                        fontSize = 11.sp,
                        maxLines = 1,
                        color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                },
                icon = {
                    Icon(
                        imageVector = icon,
                        contentDescription = tab.title,
                        tint = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp)
                    )
                }
            )
        }
    }
}
