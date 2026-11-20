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
    color: "#0D121D"

    property string notice: "Connect to your self-hosted DNS instance."
    property string queryCount: "—"
    property string blockedCount: "—"
    property string failureCount: "—"
    property string ruleCount: "—"

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
                    root.queryCount = String(data.queries)
                    root.blockedCount = String(data.blocked)
                    root.failureCount = String(data.upstream_errors)
                    root.ruleCount = String(data.rules)
                    root.notice = "Connected. Aggregate counters since restart."
                } catch (error) { root.notice = "Invalid server response." }
            } else { root.notice = "Connection failed (" + request.status + ")." }
        }
        request.open("GET", address + "/api/v1/status")
        request.setRequestHeader("Authorization", "Bearer " + token.text)
        request.send()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 30
        spacing: 16
        Label { text: "GoreeCloud DNS"; font.pixelSize: 30; font.bold: true; color: "#F2F4FB" }
        Label { text: "Native Linux console · Qt Quick 6.12.0"; color: "#CED5E5" }
        Label { text: "API endpoint"; color: "#F2F4FB" }
        TextField { id: baseUrl; Layout.fillWidth: true; text: "http://127.0.0.1:8080"; placeholderText: "HTTPS URL" }
        Label { text: "API token (held in memory only)"; color: "#F2F4FB" }
        TextField { id: token; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: "Paste your token" }
        Button { text: "Refresh status"; onClicked: root.refresh(); enabled: token.text.length >= 16 }
        Label { text: root.notice; wrapMode: Text.WordWrap; Layout.fillWidth: true; color: "#CED5E5" }
        GridLayout {
            columns: 2
            rowSpacing: 12
            columnSpacing: 18
            Layout.fillWidth: true
            Repeater {
                model: [
                    { title: "Queries", count: root.queryCount },
                    { title: "Blocked", count: root.blockedCount },
                    { title: "Upstream errors", count: root.failureCount },
                    { title: "Rules", count: root.ruleCount }
                ]
                delegate: Rectangle {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.preferredHeight: 90
                    radius: 12
                    color: "#171D2A"
                    border.color: "#505B70"
                    ColumnLayout {
                        anchors.centerIn: parent
                        Label { text: modelData.title; color: "#CED5E5" }
                        Label { text: modelData.count; font.pixelSize: 26; font.bold: true; color: "#F2F4FB" }
                    }
                }
            }
        }
        Item { Layout.fillHeight: true }
        Label { text: "Local-first · No tracking · Requires an authorized DNS API"; color: "#CED5E5" }
    }
}
