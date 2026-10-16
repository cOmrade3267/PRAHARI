package com.prahari.spike

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    SpikeScreen()
                }
            }
        }
    }
}

@Composable
fun SpikeScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var report by remember {
        mutableStateOf(
            "Tap “Run analysis”.\n\n" +
                "This proves, on THIS device, with no root and no network:\n" +
                "  • apk-parser reads real manifest permissions\n" +
                "  • dexlib2 walks the DEX and finds dangerous API calls\n" +
                "  • whether other apps' APKs are readable here (Tier A risk)\n\n" +
                "Full output is also written to Logcat (tag: RESpike)."
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Prahari — RE Spike", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Button(
            enabled = !running,
            onClick = {
                running = true
                report = "Analyzing… (first run parses every installed app's DEX; give it a few seconds)"
                scope.launch {
                    val result = withContext(Dispatchers.Default) {
                        runCatching { ReverseEngineer(context).runFullSpike() }
                            .getOrElse { "FATAL: ${it.javaClass.name}: ${it.message}" }
                    }
                    Log.i("RESpike", result)
                    report = result
                    running = false
                }
            },
        ) {
            Text(if (running) "Analyzing…" else "Run analysis")
        }
        Spacer(Modifier.height(12.dp))
        Text(
            text = report,
            modifier = Modifier.verticalScroll(rememberScrollState()),
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        )
    }
}
