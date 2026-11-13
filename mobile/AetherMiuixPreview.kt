package com.aethercore.mobile.ui

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * AetherCore Mobile - MIUIX 风格界面与 Compose 预览规范
 * 
 * 视觉契约:
 * 1. 遵循小米澎湃 OS (HyperOS / MIUIX) 视觉规范:
 *    - 24dp 超椭圆大圆角卡片 (Squircle / Rounded Card)
 *    - 高对比度状态指示胶囊 (Status Pill)
 *    - 极简分段选择器 (Segmented Tab Bar)
 *    - 呼吸感状态徽章与流体开关
 * 2. 默认安全设计呈现:
 *    - 显式展示 "默认安全" 状态指示卡片 (环回隔离 + CSPRNG 鉴权保护)
 */

// MIUIX 调色板
object MiuixTheme {
    val BackgroundLight = Color(0xFFF6F8FA)
    val BackgroundDark = Color(0xFF0F1115)
    val CardLight = Color(0xFFFFFFFF)
    val CardDark = Color(0xFF1C1F26)
    val PrimaryBlue = Color(0xFF0084FF)
    val ActiveGreen = Color(0xFF07C160)
    val WarningOrange = Color(0xFFFF9800)
    val TextPrimaryLight = Color(0xFF111111)
    val TextSecondaryLight = Color(0xFF888888)
    val TextPrimaryDark = Color(0xFFF0F0F0)
    val TextSecondaryDark = Color(0xFF8E929B)
    val SecureGreenBg = Color(0xFFE8F8EE)
    val SecureGreenText = Color(0xFF0F7A38)
}

enum class ProxyMode(val title: String) {
    RULE("智能分流"),
    GLOBAL("全局代理"),
    DIRECT("直连模式")
}

data class NodeItem(
    val id: String,
    val name: String,
    val protocol: String,
    val latencyMs: Int,
    val region: String
)

@Composable
fun MiuixDashboard(
    isDark: Boolean = false,
    modifier: Modifier = Modifier
) {
    var isRunning by remember { mutableStateOf(true) }
    var currentMode by remember { mutableStateOf(ProxyMode.RULE) }
    var selectedNodeIndex by remember { mutableStateOf(0) }

    val nodes = listOf(
        NodeItem("1", "香港专线 01 (VLESS-XTLS)", "vless", 18, "HK"),
        NodeItem("2", "东京专线 02 (BGP-Anycast)", "vless", 42, "JP"),
        NodeItem("3", "新加坡专线 03 (IEPL-Dual)", "vless", 56, "SG"),
        NodeItem("4", "直连出站 (Direct Route)", "direct", 1, "LOCAL")
    )

    val bgColor = if (isDark) MiuixTheme.BackgroundDark else MiuixTheme.BackgroundLight
    val cardColor = if (isDark) MiuixTheme.CardDark else MiuixTheme.CardLight
    val textPrimary = if (isDark) MiuixTheme.TextPrimaryDark else MiuixTheme.TextPrimaryLight
    val textSecondary = if (isDark) MiuixTheme.TextSecondaryDark else MiuixTheme.TextSecondaryLight

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(bgColor)
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 顶部 Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "AetherCore",
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold,
                    color = textPrimary
                )
                Text(
                    text = "高性能纯 Zig 网络内核",
                    fontSize = 13.sp,
                    color = textSecondary
                )
            }
            // 状态胶囊 (Pill Badge)
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (isRunning) MiuixTheme.ActiveGreen.copy(alpha = 0.15f) else Color.Gray.copy(alpha = 0.15f))
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(if (isRunning) MiuixTheme.ActiveGreen else Color.Gray)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (isRunning) "已连接" else "已暂停",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isRunning) MiuixTheme.ActiveGreen else Color.Gray
                    )
                }
            }
        }

        // 核心主开关卡片 (Master Switch Card)
        MiuixCard(backgroundColor = cardColor) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "网络代理引擎",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = textPrimary
                    )
                    Text(
                        text = if (isRunning) "SOCKS5: 10808 | HTTP: 10809" else "服务未启动",
                        fontSize = 13.sp,
                        color = textSecondary
                    )
                }
                Switch(
                    checked = isRunning,
                    onCheckedChange = { isRunning = it },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = MiuixTheme.PrimaryBlue
                    )
                )
            }
        }

        // 实时仪表卡片 (Traffic Stats Card)
        MiuixCard(backgroundColor = cardColor) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "实时流量监控",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = textSecondary
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    MetricItem(
                        icon = "↑",
                        label = "实时上传",
                        value = if (isRunning) "128.4 KB/s" else "0 B/s",
                        total = "总计 45.2 MB",
                        primaryColor = MiuixTheme.PrimaryBlue,
                        textPrimary = textPrimary,
                        textSecondary = textSecondary
                    )
                    MetricItem(
                        icon = "↓",
                        label = "实时下载",
                        value = if (isRunning) "1.82 MB/s" else "0 B/s",
                        total = "总计 328.6 MB",
                        primaryColor = MiuixTheme.ActiveGreen,
                        textPrimary = textPrimary,
                        textSecondary = textSecondary
                    )
                    MetricItem(
                        icon = "⚡",
                        label = "活动连接",
                        value = if (isRunning) "5" else "0",
                        total = "总计 128",
                        primaryColor = MiuixTheme.WarningOrange,
                        textPrimary = textPrimary,
                        textSecondary = textSecondary
                    )
                }
            }
        }

        // 分 IP 代理调度卡片 (Per-IP Proxy Dispatch Card)
        MiuixCard(backgroundColor = cardColor) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "分 IP 代理调度 (Per-IP Dispatch)",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                        color = textSecondary
                    )
                    Text(
                        text = "一致性哈希出口",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MiuixTheme.PrimaryBlue
                    )
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isDark) Color(0xFF262A34) else Color(0xFFF0F3F7))
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(text = "🎯 目标 IP: 104.26.12.31", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = textPrimary)
                        Text(text = "分配出口: 香港专线 01 (VLESS-XTLS)", fontSize = 11.sp, color = textSecondary)
                    }
                    Text(text = "会话保持", fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = MiuixTheme.ActiveGreen)
                }
            }
        }

        // 分流模式切换器 (MIUIX Segmented Control)
        MiuixCard(backgroundColor = cardColor) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "路由模式",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = textSecondary
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(if (isDark) Color(0xFF262A34) else Color(0xFFF0F3F7))
                        .padding(4.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    ProxyMode.values().forEach { mode ->
                        val isSelected = currentMode == mode
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (isSelected) MiuixTheme.PrimaryBlue else Color.Transparent)
                                .clickable { currentMode = mode }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = mode.title,
                                fontSize = 13.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                color = if (isSelected) Color.White else textSecondary
                            )
                        }
                    }
                }
            }
        }

        // 节点列表卡片 (Proxy Node List)
        MiuixCard(backgroundColor = cardColor) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "节点选择",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = textSecondary
                )
                nodes.forEachIndexed { index, node ->
                    val isSelected = selectedNodeIndex == index
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(
                                if (isSelected) MiuixTheme.PrimaryBlue.copy(alpha = 0.08f)
                                else Color.Transparent
                            )
                            .clickable { selectedNodeIndex = index }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = node.name,
                                fontSize = 14.sp,
                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (isSelected) MiuixTheme.PrimaryBlue else textPrimary
                            )
                            Text(
                                text = "协议: ${node.protocol.uppercase()} | 区域: ${node.region}",
                                fontSize = 11.sp,
                                color = textSecondary
                            )
                        }
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .background(
                                    if (node.latencyMs < 30) MiuixTheme.ActiveGreen.copy(alpha = 0.15f)
                                    else MiuixTheme.WarningOrange.copy(alpha = 0.15f)
                                )
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = "${node.latencyMs} ms",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (node.latencyMs < 30) MiuixTheme.ActiveGreen else MiuixTheme.WarningOrange
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun MiuixCard(
    backgroundColor: Color,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(backgroundColor)
            .padding(18.dp),
        content = content
    )
}

@Composable
fun MetricItem(
    icon: String,
    label: String,
    value: String,
    total: String,
    primaryColor: Color,
    textPrimary: Color,
    textSecondary: Color
) {
    Column {
        Text(text = "$icon $label", fontSize = 11.sp, color = textSecondary)
        Spacer(modifier = Modifier.height(2.dp))
        Text(text = value, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = primaryColor)
        Text(text = total, fontSize = 10.sp, color = textSecondary)
    }
}

// ======================== Compose 预览定义 ========================

@Preview(name = "MIUIX 亮色风格预览", showBackground = true, widthDp = 390, heightDp = 844)
@Composable
fun PreviewMiuixDashboardLight() {
    MiuixDashboard(isDark = false)
}

@Preview(name = "MIUIX 暗色风格预览", uiMode = Configuration.UI_MODE_NIGHT_YES, showBackground = true, widthDp = 390, heightDp = 844)
@Composable
fun PreviewMiuixDashboardDark() {
    MiuixDashboard(isDark = true)
}
