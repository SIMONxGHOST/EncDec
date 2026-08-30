package com.example.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkColorScheme = darkColorScheme(
    primary = GeoPrimaryDark,
    onPrimary = GeoOnPrimaryDark,
    primaryContainer = GeoPrimaryContainerDark,
    onPrimaryContainer = GeoOnPrimaryContainerDark,
    secondary = GeoSecondaryDark,
    onSecondary = GeoOnSecondaryDark,
    secondaryContainer = GeoSecondaryContainerDark,
    onSecondaryContainer = GeoOnSecondaryContainerDark,
    tertiary = GeoTertiaryDark,
    onTertiary = GeoOnTertiaryDark,
    tertiaryContainer = GeoTertiaryContainerDark,
    onTertiaryContainer = GeoOnTertiaryContainerDark,
    background = GeoBgDark,
    onBackground = GeoTextPrimaryDark,
    surface = GeoSurfaceDark,
    onSurface = GeoTextPrimaryDark,
    surfaceVariant = GeoSurfaceVariantDark,
    onSurfaceVariant = GeoTextSecondaryDark,
    outline = GeoOutlineDark,
    outlineVariant = GeoOutlineVariantDark,
    error = GeoDangerDark
)

private val LightColorScheme = lightColorScheme(
    primary = GeoPrimaryLight,
    onPrimary = GeoOnPrimaryLight,
    primaryContainer = GeoPrimaryContainerLight,
    onPrimaryContainer = GeoOnPrimaryContainerLight,
    secondary = GeoSecondaryLight,
    onSecondary = GeoOnSecondaryLight,
    secondaryContainer = GeoSecondaryContainerLight,
    onSecondaryContainer = GeoOnSecondaryContainerLight,
    tertiary = GeoTertiaryLight,
    onTertiary = GeoOnTertiaryLight,
    tertiaryContainer = GeoTertiaryContainerLight,
    onTertiaryContainer = GeoOnTertiaryContainerLight,
    background = GeoBgLight,
    onBackground = GeoTextPrimaryLight,
    surface = GeoSurfaceLight,
    onSurface = GeoTextPrimaryLight,
    surfaceVariant = GeoSurfaceVariantLight,
    onSurfaceVariant = GeoTextSecondaryLight,
    outline = GeoOutlineLight,
    outlineVariant = GeoOutlineVariantLight,
    error = GeoDangerLight
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
