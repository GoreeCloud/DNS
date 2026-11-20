package com.goreecloud.dns

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { DNSConsole() } }
    }
}

private data class ResolverStatus(val queries: Long, val blocked: Long, val errors: Long, val rules: Long)

private suspend fun fetchStatus(base: String, token: String): ResolverStatus =
    withContext(Dispatchers.IO) {
        val server = base.trim().trimEnd('/')
        require(server.startsWith("https://", ignoreCase = true)) {
            "A trusted HTTPS endpoint is required on Android."
        }
        require(token.length >= 16) { "Enter your API token." }
        val connection = (URL(server + "/api/v1/status").openConnection() as HttpURLConnection)
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.useCaches = false
            connection.setRequestProperty("Authorization", "Bearer " + token)
            if (connection.responseCode != 200) {
                throw IllegalStateException("Server returned HTTP " + connection.responseCode)
            }
            val payload = connection.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(payload)
            ResolverStatus(json.getLong("queries"), json.getLong("blocked"),
                json.getLong("upstream_errors"), json.getLong("rules"))
        } finally {
            connection.disconnect()
        }
    }

@Composable
private fun DNSConsole() {
    var endpoint by remember { mutableStateOf("https://") }
    var token by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<ResolverStatus?>(null) }
    var notice by remember { mutableStateOf("Connect to a trusted GoreeCloud DNS server.") }
    var loading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("GoreeCloud DNS", style = MaterialTheme.typography.headlineMedium)
        Text("Private resolver console", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = endpoint, onValueChange = { endpoint = it },
            label = { Text("HTTPS server URL") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = token, onValueChange = { token = it },
            label = { Text("API token (not stored)") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        Button(
            enabled = !loading && token.length >= 16,
            onClick = {
                loading = true
                notice = "Connecting…"
                scope.launch {
                    try {
                        status = fetchStatus(endpoint, token)
                        notice = "Connected · Aggregate counters since restart"
                    } catch (error: Exception) {
                        status = null
                        notice = error.message ?: "Connection error"
                    } finally { loading = false }
                }
            }
        ) { Text(if (loading) "Loading" else "Refresh status") }
        Text(notice, style = MaterialTheme.typography.bodyMedium)
        status?.let { data ->
            Metric("Total DNS queries", data.queries)
            Metric("Blocked queries", data.blocked)
            Metric("Upstream failures", data.errors)
            Metric("Active policy rules", data.rules)
            Button(onClick = {
                status = null
                token = ""
                notice = "Disconnected; API token cleared."
            }) { Text("Disconnect") }
        }
        Text("No client IPs, location, or query history is collected by this console.")
    }
}

@Composable
private fun Metric(label: String, value: Long) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp)) {
            Text(label, style = MaterialTheme.typography.labelLarge)
            Text(value.toString(), style = MaterialTheme.typography.headlineMedium)
        }
    }
}
