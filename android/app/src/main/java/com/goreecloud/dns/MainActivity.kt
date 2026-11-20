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
        setContent { GoreeCloudTheme { DNSConsole() } }
    }
}

private data class ResolverStatus(
    val queries: Long,
    val blocked: Long,
    val errors: Long,
    val rules: Long,
    val exceptions: Long,
    val overloaded: Long,
    val upstreamMode: String
)

private suspend fun apiRequest(
    base: String, token: String, path: String, payload: JSONObject? = null
): JSONObject = withContext(Dispatchers.IO) {
    val server = base.trim().trimEnd('/')
    val origin = URL(server)
    require(origin.protocol == "https" && origin.host.isNotBlank() && origin.userInfo == null) {
        "A trusted HTTPS endpoint without embedded credentials is required."
    }
    require(token.length >= 16) { "Enter your API token." }
    val connection = (URL(server + path).openConnection() as HttpURLConnection)
    try {
        connection.instanceFollowRedirects = false
        connection.requestMethod = if (payload == null) "GET" else "POST"
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        connection.useCaches = false
        connection.setRequestProperty("Authorization", "Bearer " + token)
        connection.setRequestProperty("Accept", "application/json")
        if (payload != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(payload.toString()) }
        }
        if (connection.responseCode != 200) {
            throw IllegalStateException("Server returned HTTP " + connection.responseCode)
        }
        val data = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        JSONObject(data)
    } finally {
        connection.disconnect()
    }
}

private suspend fun fetchStatus(base: String, token: String): ResolverStatus {
    val data = apiRequest(base, token, "/api/v1/status")
    return ResolverStatus(
        data.getLong("queries"),
        data.getLong("blocked"),
        data.getLong("upstream_errors"),
        data.getLong("rules"),
        data.getLong("exceptions"),
        data.getLong("overloaded"),
        data.getString("upstream_mode")
    )
}

private suspend fun checkPolicy(base: String, token: String, name: String): String {
    require(name.isNotBlank() && name.length <= 253) { "Enter one valid DNS domain." }
    val json = apiRequest(base, token, "/api/v1/policy/check", JSONObject().put("name", name))
    return json.getString("name") + ": " + when (json.getString("decision")) {
        "allowed" -> "explicitly allowed"
        "blocked" -> "blocked by local policy"
        "unmatched" -> "no rule matched; forwarded when queried"
        else -> "unknown policy decision"
    }
}

@Composable
private fun DNSConsole() {
    var endpoint by remember { mutableStateOf("https://") }
    var token by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<ResolverStatus?>(null) }
    var domain by remember { mutableStateOf("") }
    var decision by remember { mutableStateOf("") }
    var notice by remember { mutableStateOf("Connect to your private GoreeCloud DNS server.") }
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
            label = { Text("HTTPS server URL") },
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = token, onValueChange = { token = it },
            label = { Text("API token (held in memory only)") },
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
                        notice = "Connected · Aggregates since server restart"
                    } catch (e: Exception) {
                        status = null
                        notice = when (e) {
                            is IllegalArgumentException, is IllegalStateException ->
                                e.message ?: "Invalid settings"
                            else -> "Connection or TLS verification failed"
                        }
                    } finally { loading = false }
                }
            }
        ) { Text(if (loading) "Loading" else "Refresh status") }
        Text(notice, style = MaterialTheme.typography.bodyMedium)
        status?.let { data ->
            Metric("Total queries", data.queries)
            Metric("Blocked queries", data.blocked)
            Metric("Upstream failures", data.errors)
            Metric("Rejected overloads", data.overloaded)
            Metric("Active rules", data.rules)
            Metric("Allow exceptions", data.exceptions)
            Text("Upstream transport: " + data.upstreamMode)
            Text("Check a domain against local policy without generating DNS traffic.",
                style = MaterialTheme.typography.bodyMedium)
            OutlinedTextField(
                value = domain,
                onValueChange = { domain = it; decision = "" },
                label = { Text("Domain name") },
                singleLine = true, modifier = Modifier.fillMaxWidth()
            )
            Button(
                enabled = !loading && domain.isNotBlank() && domain.length <= 253,
                onClick = {
                    loading = true
                    scope.launch {
                        try {
                            decision = checkPolicy(endpoint, token, domain.trim())
                        } catch (e: Exception) {
                            decision = when (e) {
                                is IllegalArgumentException, is IllegalStateException ->
                                    e.message ?: "Invalid domain"
                                else -> "Could not check policy"
                            }
                        } finally { loading = false }
                    }
                }
            ) { Text("Check policy") }
            if (decision.isNotEmpty()) {
                Text(decision, style = MaterialTheme.typography.bodyMedium)
            }
            Button(onClick = {
                status = null
                token = ""
                domain = ""
                decision = ""
                notice = "Disconnected; token and result cleared."
            }) { Text("Disconnect") }
        }
        Text("No individual DNS query history or device IPs are stored by this app.")
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
