import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    width: 760
    height: 700
    minimumWidth: 480
    minimumHeight: 480
    visible: true
    title: "GoreeCloud DNS"
    color: "#0D121D"

    // Canonical alpha semantic colors from GoreeCloud/gc-ui pinned in the
    // repository. Native runtime/visual acceptance is still outstanding.
    property string notice: "Connect to your self-hosted DNS instance."
    property string policyNotice: ""
    property string queryCount: "—"
    property string blockedCount: "—"
    property string failureCount: "—"
    property string overloadCount: "—"
    property string ruleCount: "—"
    property string exceptionCount: "—"
    property string upstreamMode: "—"

    function validAddress() {
        var address = baseUrl.text.trim().replace(/\/+$/, "")
        return address.startsWith("https://") ||
            address.startsWith("http://127.0.0.1:") ||
            address.startsWith("http://localhost:")
    }

    function refresh() {
        if (!validAddress()) {
            notice = "Use trusted HTTPS or localhost HTTP."
            return
        }
        if (token.text.length < 16) { notice = "Enter your API token."; return }
        notice = "Connecting…"
        var address = baseUrl.text.trim().replace(/\/+$/, "")
        var request = new XMLHttpRequest()
        request.onreadystatechange = function() {
            if (request.readyState !== XMLHttpRequest.DONE) return
            if (request.status === 200) {
                try {
                    var data = JSON.parse(request.responseText)
                    root.queryCount = String(data.queries)
                    root.blockedCount = String(data.blocked)
                    root.failureCount = String(data.upstream_errors)
                    root.overloadCount = String(data.overloaded)
                    root.ruleCount = String(data.rules)
                    root.exceptionCount = String(data.exceptions)
                    root.upstreamMode = String(data.upstream_mode)
                    root.notice = "Connected · Aggregate counters since restart"
                } catch (error) {
                    root.notice = "Invalid server response."
                }
            } else {
                root.notice = "Connection failed (" + request.status + ")."
            }
        }
        request.open("GET", address + "/api/v1/status")
        request.setRequestHeader("Authorization", "Bearer " + token.text)
        request.send()
    }

    function checkPolicy() {
        if (!validAddress() || token.text.length < 16) {
            policyNotice = "Connect before checking a domain."
            return
        }
        if (domainInput.text.trim().length === 0 || domainInput.text.length > 253) {
            policyNotice = "Enter a valid DNS domain."
            return
        }
        var address = baseUrl.text.trim().replace(/\/+$/, "")
        var request = new XMLHttpRequest()
        policyNotice = "Checking…"
        request.onreadystatechange = function() {
            if (request.readyState !== XMLHttpRequest.DONE) return
            if (request.status === 200) {
                try {
                    var data = JSON.parse(request.responseText)
                    root.policyNotice = String(data.name) + ": " + String(data.decision)
                } catch (error) { root.policyNotice = "Invalid server response." }
            } else { root.policyNotice = "Policy check rejected (" + request.status + ")." }
        }
        request.open("POST", address + "/api/v1/policy/check")
        request.setRequestHeader("Authorization", "Bearer " + token.text)
        request.setRequestHeader("Content-Type", "application/json")
        request.send(JSON.stringify({name: domainInput.text.trim()}))
    }

    ScrollView {
        anchors.fill: parent
        id: scroll
        contentWidth: availableWidth
        ColumnLayout {
            width: scroll.availableWidth
            anchors.margins: 30
            spacing: 14
            Label {
                text: "GoreeCloud DNS"
                font.pixelSize: 30
                font.bold: true
                color: "#F2F4FB"
                Layout.topMargin: 22
                Layout.leftMargin: 30
            }
            Label {
                text: "Native Linux console · Qt Quick 6.12.0"
                color: "#CED5E5"
                Layout.leftMargin: 30
            }
            Label { text: "API endpoint"; color: "#F2F4FB"; Layout.leftMargin: 30 }
            TextField {
                id: baseUrl
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                text: "http://127.0.0.1:8080"
                placeholderText: "Trusted HTTPS URL"
            }
            Label { text: "API token (held in memory only)"; color: "#F2F4FB"; Layout.leftMargin: 30 }
            TextField {
                id: token
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                echoMode: TextInput.Password
                placeholderText: "Paste your token"
            }
            Button {
                text: "Refresh status"
                Layout.leftMargin: 30
                onClicked: root.refresh()
                enabled: token.text.length >= 16
            }
            Label {
                text: root.notice
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                color: "#CED5E5"
            }
            GridLayout {
                columns: 2
                rowSpacing: 12
                columnSpacing: 18
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                Repeater {
                    model: [
                        { title: "Queries", count: root.queryCount },
                        { title: "Blocked", count: root.blockedCount },
                        { title: "Upstream errors", count: root.failureCount },
                        { title: "Overload refusals", count: root.overloadCount },
                        { title: "Rules", count: root.ruleCount },
                        { title: "Exceptions", count: root.exceptionCount }
                    ]
                    delegate: Rectangle {
                        required property var modelData
                        Layout.fillWidth: true
                        Layout.preferredHeight: 88
                        radius: 12
                        color: "#171D2A"
                        border.color: "#505B70"
                        ColumnLayout {
                            anchors.centerIn: parent
                            Label { text: modelData.title; color: "#CED5E5" }
                            Label {
                                text: modelData.count
                                font.pixelSize: 26
                                font.bold: true
                                color: "#F2F4FB"
                            }
                        }
                    }
                }
            }
            Label {
                text: "Upstream mode: " + root.upstreamMode
                color: "#CED5E5"
                Layout.leftMargin: 30
            }
            Label {
                text: "Check domain policy without performing a DNS query"
                color: "#F2F4FB"
                Layout.leftMargin: 30
            }
            TextField {
                id: domainInput
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                Layout.fillWidth: true
                placeholderText: "example.org"
                maximumLength: 253
                onTextChanged: root.policyNotice = ""
            }
            Button {
                text: "Check local policy"
                Layout.leftMargin: 30
                onClicked: root.checkPolicy()
                enabled: token.text.length >= 16 && domainInput.text.trim().length > 0
            }
            Label {
                text: root.policyNotice
                color: "#CED5E5"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
            }
            Button {
                text: "Disconnect and clear token"
                Layout.leftMargin: 30
                onClicked: {
                    token.text = ""
                    domainInput.text = ""
                    root.policyNotice = ""
                    root.notice = "Disconnected."
                }
            }
            Label {
                text: "Local-first · No query history · No tracking"
                color: "#CED5E5"
                Layout.leftMargin: 30
                Layout.bottomMargin: 30
            }
        }
    }
}
