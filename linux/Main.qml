import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    width: 720
    height: 570
    minimumWidth: 480
    minimumHeight: 470
    visible: true
    title: "GoreeCloud DNS"

    property string notice: "Connect to your self-hosted DNS instance."
    property bool connected: false

    function refresh() {
        var address = baseUrl.text.trim().replace(/\/+$/, "")
        if (!(address.startsWith("https://") || address.startsWith("http://127.0.0.1:") || address.startsWith("http://localhost:"))) {
            notice = "Use HTTPS or localhost HTTP."
            return
        }
        if (token.text.length < 16) { notice = "Enter your API token."; return }
        notice = "Connecting..."
        var request = new XMLHttpRequest()
        request.onreadystatechange = function() {
            if (request.readyState !== XMLHttpRequest.DONE) return
            if (request.status === 200) {
                try {
                    var data = JSON.parse(request.responseText)
                    queries.text = String(data.queries)
                    blocked.text = String(data.blocked)
                    failures.text = String(data.upstream_errors)
                    rules.text = String(data.rules)
                    root.connected = true
                    root.notice = "Connected. Statistics are aggregate counters since restart."
                } catch (error) { root.notice = "Invalid server response."; root.connected = false }
            } else { root.notice = "Connection failed (" + request.status + ")."; root.connected = false }
        }
        request.open("GET", address + "/api/v1/status")
        request.setRequestHeader("Authorization", "Bearer " + token.text)
        request.send()
    }

    color: "#0b111c"
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 30
        spacing: 16
        Label { text: "GoreeCloud DNS"; font.pixelSize: 30; font.bold: true; color: "#f1f5fb" }
        Label { text: "Linux native console · Qt Quick 6.12.0"; color: "#b2c0d4" }
        Label { text: "API endpoint"; color: "#dce8fa" }
        TextField { id: baseUrl; Layout.fillWidth: true; text: "http://127.0.0.1:8080"; placeholderText: "HTTPS URL" }
        Label { text: "API token (held in memory only)"; color: "#dce8fa" }
        TextField { id: token; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: "Paste your token" }
        Button { text: "Refresh status"; onClicked: root.refresh(); enabled: token.text.length >= 16 }
        Label { text: root.notice; wrapMode: Text.WordWrap; Layout.fillWidth: true; color: "#b2c0d4" }
        GridLayout {
            columns: 2
            rowSpacing: 12
            columnSpacing: 18
            Layout.fillWidth: true
            Repeater {
                model: [ "Queries", "Blocked", "Upstream errors", "Rules" ]
                delegate: Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 90
                    radius: 12
                    color: "#172438"
                    border.color: "#304461"
                    ColumnLayout {
                        anchors.centerIn: parent
                        Label { text: modelData; color: "#b2c0d4" }
                        Label { id: valueLabel; text: "—"; font.pixelSize: 26; font.bold: true; color: "#fff" }
                    }
                }
            }
        }
        // Separate hidden status labels keep state independent of repeater lifetime.
        Item { visible: false; Label { id: queries; text: "0" }; Label { id: blocked; text: "0" }; Label { id: failures; text: "0" }; Label { id: rules; text: "0" } }
        Item { Layout.fillHeight: true }
        Label { text: "Local-first · No tracking · Requires an authorized DNS API"; color: "#8ba0bd" }
    }
}
