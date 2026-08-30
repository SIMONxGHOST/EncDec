package com.example.ui.screens

import android.content.Context
import android.content.Intent
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.LogStatus
import com.example.ui.theme.GeoDangerDark
import com.example.ui.theme.GeoDangerLight
import com.example.ui.theme.GeoSuccessDark
import com.example.ui.theme.GeoSuccessLight
import com.example.viewmodel.EncDecUiState

@Composable
fun TextCryptoScreen(
    state: EncDecUiState,
    onPlainTextChange: (String) -> Unit,
    onCipherTextChange: (String) -> Unit,
    onUseEnvelopeChange: (Boolean) -> Unit,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onTransferToQr: () -> Unit,
    modifier: Modifier = Modifier,
    headerContent: (@Composable () -> Unit)? = null
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (headerContent != null) {
            headerContent()
        }

        // Plaintext Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.LockOpen,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = "Decrypted Plaintext",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                        IconButton(
                            onClick = {
                                if (state.plainText.isNotBlank()) {
                                    val sendIntent = Intent().apply {
                                        action = Intent.ACTION_SEND
                                        putExtra(Intent.EXTRA_TEXT, state.plainText)
                                        type = "text/plain"
                                    }
                                    context.startActivity(Intent.createChooser(sendIntent, "Share Plaintext"))
                                }
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = "Share Plaintext",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = {
                                clipboardManager.getText()?.let { onPlainTextChange(it.text) }
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.ContentPaste,
                                contentDescription = "Paste Plaintext",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(state.plainText))
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.ContentCopy,
                                contentDescription = "Copy Plaintext",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = { onPlainTextChange("") },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Clear,
                                contentDescription = "Clear Plaintext",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = state.plainText,
                    onValueChange = onPlainTextChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 110.dp),
                    minLines = 4,
                    maxLines = 8,
                    placeholder = { Text("Type or paste confidential message here...", fontSize = 13.sp) },
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant
                    ),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
                )

                val wordsCount = if (state.plainText.isBlank()) 0 else state.plainText.trim().split("\\s+".toRegex()).size
                val bytesCount = state.plainText.toByteArray(Charsets.UTF_8).size
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "${state.plainText.length} chars | $wordsCount words | $bytesCount B",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "UTF-8 Plaintext",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Action Hub & Envelope Setting
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(
                    onClick = onEncrypt,
                    enabled = !state.isTextProcessing,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    )
                ) {
                    if (state.isTextProcessing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                            Text("Encrypt 🔒", fontWeight = FontWeight.Bold)
                        }
                    }
                }

                FilledTonalButton(
                    onClick = onDecrypt,
                    enabled = !state.isTextProcessing,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.filledTonalButtonColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("🔓 Decrypt", fontWeight = FontWeight.Bold)
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Checkbox(
                    checked = state.useEnvelope,
                    onCheckedChange = onUseEnvelopeChange,
                    colors = CheckboxDefaults.colors(checkedColor = MaterialTheme.colorScheme.primary)
                )
                Text(
                    text = "ENC5 Self-Describing Envelope (Auto Key Tier)",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1
                )
            }
        }

        // Ciphertext Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        modifier = Modifier.weight(1f, fill = false),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = "Encrypted Ciphertext",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1
                        )
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                        IconButton(
                            onClick = onTransferToQr,
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.QrCode,
                                contentDescription = "Transfer to QR Studio",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = {
                                if (state.cipherText.isNotBlank()) {
                                    val sendIntent = Intent().apply {
                                        action = Intent.ACTION_SEND
                                        putExtra(Intent.EXTRA_TEXT, state.cipherText)
                                        type = "text/plain"
                                    }
                                    context.startActivity(Intent.createChooser(sendIntent, "Share Ciphertext"))
                                }
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = "Share Ciphertext",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(state.cipherText))
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.ContentCopy,
                                contentDescription = "Copy Ciphertext",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        IconButton(
                            onClick = { onCipherTextChange("") },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Clear,
                                contentDescription = "Clear Ciphertext",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = state.cipherText,
                    onValueChange = onCipherTextChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 110.dp),
                    minLines = 4,
                    maxLines = 8,
                    placeholder = { Text("Encrypted ciphertext token will appear here...", fontSize = 12.sp) },
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant
                    ),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${state.cipherText.length} chars | ${state.cipherText.toByteArray(Charsets.UTF_8).size} B",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    if (state.cipherText.isNotBlank()) {
                        val format = state.detectedCipherFormat
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "• ${format.formatName}",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (format.isEncrypted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            if (format.confidenceBadge.isNotBlank()) {
                                Text(
                                    text = "(${format.confidenceBadge})",
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.outline
                                )
                            }
                        }
                    } else {
                        Text(
                            text = "Auto-Format Detector Ready",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        // Live Status Banner
        val isDark = MaterialTheme.colorScheme.surface.red < 0.5f
        val statusColor = when (state.textStatusType) {
            LogStatus.SUCCESS -> if (isDark) GeoSuccessDark else GeoSuccessLight
            LogStatus.FAILED -> if (isDark) GeoDangerDark else GeoDangerLight
            LogStatus.INFO -> MaterialTheme.colorScheme.primary
        }

        val infiniteTransition = rememberInfiniteTransition(label = "pulse")
        val pulseScale by infiniteTransition.animateFloat(
            initialValue = 0.9f,
            targetValue = 1.25f,
            animationSpec = infiniteRepeatable(
                animation = tween(800),
                repeatMode = RepeatMode.Reverse
            ),
            label = "beaconScale"
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.3f))
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .scale(if (state.isTextProcessing) pulseScale else 1f)
                        .clip(CircleShape)
                        .background(statusColor)
                )
                Text(
                    text = state.textStatusMessage,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}
