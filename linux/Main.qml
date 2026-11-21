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
    property string refusedCount: "—"
    property string rateLimitedCount: "—"
    property string rateQps: "—"
    property string rateBurst: "—"
    property string localRecordsCount: "—"
    property string localAnswersCount: "—"
    property string ruleCount: "—"
    property string exceptionCount: "—"
    property string upstreamMode: "—"
    property string inboundDoT: "—"
    property string inboundDoH: "—"

    // Networking is handled by native QtNetwork, not QML XMLHttpRequest.
    // Validation rejects deceptive credentials-in-URL and plain HTTP to
    // remote hosts, while requests refuse redirects and verify system TLS.
    function validAddress() {
        return dnsApi.endpointAllowed(baseUrl.text)
    }

    function refresh() {
        if (token.text.length < 16) {
            notice = "Enter an API token before connecting."
            return
        }
        notice = "Connecting…"
        dnsApi.fetchStatus(baseUrl.text, token.text)
    }

    function reloadLocal() {
        if (token.text.length < 16) {
            notice = "Connect before reloading local records."
            return
        }
        notice = "Reloading validated local DNS records…"
        dnsApi.reloadLocal(baseUrl.text, token.text)
    }

    function checkPolicy() {
        if (token.text.length < 16) {
            policyNotice = "Connect before checking a domain."
            return
        }
        policyNotice = "Checking…"
        dnsApi.checkPolicy(baseUrl.text, token.text, domainInput.text)
    }

    function clearCounters() {
        queryCount = "—"
        blockedCount = "—"
        failureCount = "—"
        overloadCount = "—"
        refusedCount = "—"
        rateLimitedCount = "—"
        rateQps = "—"
        rateBurst = "—"
        localRecordsCount = "—"
        localAnswersCount = "—"
        ruleCount = "—"
        exceptionCount = "—"
        upstreamMode = "—"
    }

    Connections {
        target: dnsApi
        function onStatusReady(data) {
            root.queryCount = String(data.queries)
            root.blockedCount = String(data.blocked)
            root.failureCount = String(data.upstream_errors)
            root.overloadCount = String(data.overloaded)
            root.refusedCount = String(data.refused)
            root.rateLimitedCount = String(data.rate_limited)
            root.rateQps = String(data.rate_qps)
            root.rateBurst = String(data.rate_burst)
            root.localRecordsCount = String(data.local_records)
            root.localAnswersCount = String(data.local_answers)
            root.ruleCount = String(data.rules)
            root.exceptionCount = String(data.exceptions)
            root.upstreamMode = String(data.upstream_mode)
            root.inboundDoT = data.inbound_dot_enabled ? "enabled" : "disabled"
            root.inboundDoH = data.inbound_doh_enabled ? "enabled" : "disabled"
            root.notice = "Connected · Aggregate counters since restart"
        }
        function onPolicyReady(name, decision) {
            root.policyNotice = name + ": " + decision
        }
        function onLocalReloaded() {
            root.notice = "Local records reloaded. Refreshing status…"
            root.refresh()
        }
        function onRequestFailed(action, reason) {
            if (action === "policy") {
                root.policyNotice = reason
            } else {
                root.notice = reason
            }
        }
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
                onTextChanged: {
                    dnsApi.clearSession()
                    root.clearCounters()
                    root.notice = "Endpoint changed; connect to refresh."
                }
            }
            Label { text: "API token (held in memory only)"; color: "#F2F4FB"; Layout.leftMargin: 30 }
            TextField {
                id: token
                Layout.fillWidth: true
                Layout.leftMargin: 30
                Layout.rightMargin: 30
                echoMode: TextInput.Password
                placeholderText: "Paste your token"
                onTextChanged: {
                    dnsApi.clearSession()
                    root.clearCounters()
                }
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
                        { title: "Refused clients", count: root.refusedCount },
                        { title: "Rate-limited", count: root.rateLimitedCount },
                        { title: "Local records", count: root.localRecordsCount },
                        { title: "Local answers", count: root.localAnswersCount },
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
            Button {
                text: "Reload local DNS records"
                Layout.leftMargin: 30
                onClicked: root.reloadLocal()
                enabled: token.text.length >= 16
            }
            Label {
                text: "Global query budget: " + root.rateQps + "/s, burst " + root.rateBurst
                color: "#CED5E5"
                Layout.leftMargin: 30
            }
            Label {
                text: "Inbound DNS-over-HTTPS: " + root.inboundDoH
                color: "#CED5E5"
                Layout.leftMargin: 30
            }
            Label {
                text: "Inbound DNS-over-TLS: " + root.inboundDoT
                color: "#CED5E5"
                Layout.leftMargin: 30
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
                textFormat: Text.PlainText
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
                    dnsApi.clearSession()
                    token.text = ""
                    domainInput.text = ""
                    root.clearCounters()
                    root.policyNotice = ""
                    root.notice = "Disconnected. Session and pending requests cleared."
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
