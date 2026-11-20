package com.goreecloud.dns

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Semantic roles pinned to GoreeCloud/gc-ui tokens/gc.tokens.json
// at be6fdda0dfa9ca509c01bafb9ed483a272fa821b (MIT, alpha).
private val GoreeCloudLightColors = lightColorScheme(
    primary = Color(0xFF5146C8),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFFF6F7FB),
    onBackground = Color(0xFF1B2030),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1B2030),
    surfaceVariant = Color(0xFFEEF0F7),
    onSurfaceVariant = Color(0xFF505B70),
    outline = Color(0xFF68758C),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF)
)
private val GoreeCloudDarkColors = darkColorScheme(
    primary = Color(0xFFBFB8FF),
    onPrimary = Color(0xFF272057),
    background = Color(0xFF0D121D),
    onBackground = Color(0xFFF2F4FB),
    surface = Color(0xFF171D2A),
    onSurface = Color(0xFFF2F4FB),
    surfaceVariant = Color(0xFF252D3D),
    onSurfaceVariant = Color(0xFFCED5E5),
    outline = Color(0xFF9CA8BC),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF4F1410)
)

@Composable
fun GoreeCloudTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) GoreeCloudDarkColors else GoreeCloudLightColors,
        content = content
    )
}
