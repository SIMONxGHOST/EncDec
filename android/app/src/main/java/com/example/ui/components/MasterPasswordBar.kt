package com.example.ui.components

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.crypto.EntropyResult
import com.example.crypto.KeyProfile

@Composable
fun MasterPasswordBar(
    password: String,
    onPasswordChange: (String) -> Unit,
    isPasswordVisible: Boolean,
    onToggleVisibility: () -> Unit,
    entropyResult: EntropyResult,
    selectedProfile: KeyProfile,
    onProfileSelected: (KeyProfile) -> Unit,
    autoSync: Boolean,
    onToggleAutoSync: (Boolean) -> Unit,
    keyfileName: String? = null,
    hasKeyfile: Boolean = false,
    onAttachKeyfile: (Uri, String, ByteArray) -> Unit = { _, _, _ -> },
    onRemoveKeyfile: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var dropdownExpanded by remember { mutableStateOf(false) }
    var isExpanded by remember { mutableStateOf(true) }

    val keyfileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                var fileName = "keyfile.bin"
                context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx != -1) fileName = cursor.getString(idx) ?: "keyfile.bin"
                    }
                }
                val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                if (bytes != null && bytes.isNotEmpty()) {
                    onAttachKeyfile(uri, fileName, bytes)
                }
            } catch (_: Exception) {}
        }
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { isExpanded = !isExpanded }
                    .padding(vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier.weight(1f, fill = false),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = if (isExpanded) "Master Key & Scrypt Tier" else if (password.isBlank()) "Master Key: (Not set)" else "Master Key: ••••••••",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (hasKeyfile) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(MaterialTheme.colorScheme.tertiaryContainer)
                                .padding(horizontal = 5.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = "2FA Keyfile",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                maxLines = 1
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(Color(entropyResult.colorHex).copy(alpha = 0.15f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "${entropyResult.rating} (${entropyResult.bits}b)",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(entropyResult.colorHex),
                            maxLines = 1
                        )
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "${selectedProfile.alias} (${selectedProfile.memoryMb}MB RAM)",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            maxLines = 1
                        )
                    }

                    IconButton(
                        onClick = { isExpanded = !isExpanded },
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            imageVector = if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = if (isExpanded) "Collapse key panel" else "Expand key panel",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            AnimatedVisibility(
                visible = isExpanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(top = 2.dp)
                ) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = onPasswordChange,
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Enter cryptographic passphrase...", fontSize = 12.sp) },
                        singleLine = true,
                        visualTransformation = if (isPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(
                                onClick = onToggleVisibility,
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    imageVector = if (isPasswordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = "Toggle password visibility",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        },
                        shape = RoundedCornerShape(10.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                            focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant
                        ),
                        textStyle = MaterialTheme.typography.bodyMedium.copy(
                            fontSize = 13.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    )

                    val animatedProgress by animateFloatAsState(targetValue = entropyResult.scorePercentage, label = "entropyProgress")
                    val animatedColor by animateColorAsState(targetValue = Color(entropyResult.colorHex), label = "entropyColor")
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth(animatedProgress)
                                .height(4.dp)
                                .clip(RoundedCornerShape(2.dp))
                                .background(animatedColor)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "GPU Crack Resistance: ${entropyResult.crackTimeEstimate}",
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        Spacer(modifier = Modifier.size(6.dp))
                        Text(
                            text = "Scrypt Memory-Hard • AEAD",
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .border(
                                    1.dp,
                                    MaterialTheme.colorScheme.outlineVariant,
                                    RoundedCornerShape(10.dp)
                                )
                                .clickable { dropdownExpanded = true }
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f, fill = false)) {
                                    Text(
                                        text = "Scrypt Tier (GPU-Proof)",
                                        fontSize = 9.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1
                                    )
                                    Text(
                                        text = "${selectedProfile.alias} (${selectedProfile.memoryMb}MB RAM)",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                                Icon(
                                    imageVector = Icons.Default.ArrowDropDown,
                                    contentDescription = "Select Scrypt Tier",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                            }

                            DropdownMenu(
                                expanded = dropdownExpanded,
                                onDismissRequest = { dropdownExpanded = false },
                                modifier = Modifier.background(MaterialTheme.colorScheme.surface)
                            ) {
                                KeyProfile.ALL_PROFILES.forEach { profile ->
                                    DropdownMenuItem(
                                        text = {
                                            Column {
                                                Text(
                                                    text = "${profile.alias} • ${profile.rating} (${profile.memoryMb}MB RAM)",
                                                    fontWeight = FontWeight.Bold,
                                                    fontSize = 13.sp
                                                )
                                                Text(
                                                    text = "Scrypt N=${profile.scryptN} • AES-256-GCM AEAD • ${profile.description}",
                                                    fontSize = 10.sp,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }
                                        },
                                        onClick = {
                                            onProfileSelected(profile)
                                            dropdownExpanded = false
                                        }
                                    )
                                }
                            }
                        }

                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (hasKeyfile) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant)
                                .border(
                                    1.dp,
                                    if (hasKeyfile) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                                    RoundedCornerShape(10.dp)
                                )
                                .clickable {
                                    if (hasKeyfile) {
                                        onRemoveKeyfile()
                                    } else {
                                        keyfileLauncher.launch("*/*")
                                    }
                                }
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(
                                    imageVector = if (hasKeyfile) Icons.Default.Close else Icons.Default.Fingerprint,
                                    contentDescription = "2FA Keyfile",
                                    tint = if (hasKeyfile) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(14.dp)
                                )
                                Column {
                                    Text(
                                        text = "2FA Keyfile",
                                        fontSize = 8.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Text(
                                        text = if (hasKeyfile) keyfileName?.take(8) ?: "Active" else "Attach",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (hasKeyfile) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .border(
                                    1.dp,
                                    MaterialTheme.colorScheme.outlineVariant,
                                    RoundedCornerShape(10.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 4.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Sync,
                                contentDescription = null,
                                tint = if (autoSync) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(12.dp)
                            )
                            Text(
                                text = "Auto",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1
                            )
                            Switch(
                                checked = autoSync,
                                onCheckedChange = onToggleAutoSync,
                                modifier = Modifier.height(24.dp),
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                                    checkedTrackColor = MaterialTheme.colorScheme.primary
                                )
                            )
                        }
                    }
                }
            }
        }
    }
}
