#include "DnsApiClient.h"

#include <QJsonDocument>
#include <QNetworkRequest>
#include <QVariantMap>
#include <memory>

namespace {
constexpr qsizetype kMaxResponseBytes = 64 * 1024;

struct ResponseBuffer {
    QByteArray bytes;
    bool exceeded = false;
};
}

DnsApiClient::DnsApiClient(QObject *parent) : QObject(parent) {}

bool DnsApiClient::endpointAllowed(const QString &base) const {
    const QString input = base.trimmed();
    if (input.isEmpty()) return false;
    const QUrl url(input, QUrl::StrictMode);
    if (!url.isValid() || url.isRelative() || url.host().isEmpty()
        || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()
        || (url.path() != QString() && url.path() != QStringLiteral("/"))) {
        return false;
    }
    if (url.port() == 0 || url.port() > 65535) return false;
    if (url.scheme() == QStringLiteral("https")) return true;
    if (url.scheme() != QStringLiteral("http")) return false;
    const QString host = url.host().toLower();
    return host == QStringLiteral("localhost") ||
           host == QStringLiteral("127.0.0.1") ||
           host == QStringLiteral("::1");
}

void DnsApiClient::clearSession() {
    ++generation_;
    const auto outstanding = requests_.values();
    for (QNetworkReply *reply : outstanding) {
        reply->abort();
    }
}

void DnsApiClient::fetchStatus(const QString &base, const QString &token) {
    request(QStringLiteral("status"), base, token, "/api/v1/status");
}

void DnsApiClient::reloadLocal(const QString &base, const QString &token) {
    request(QStringLiteral("local"), base, token, "/api/v1/local/reload");
}

void DnsApiClient::checkPolicy(const QString &base, const QString &token, const QString &domain) {
    const QString name = domain.trimmed();
    if (name.isEmpty() || name.size() > 253) {
        emit requestFailed(QStringLiteral("policy"), QStringLiteral("Enter one valid DNS domain."));
        return;
    }
    const QJsonObject body{{QStringLiteral("name"), name}};
    request(QStringLiteral("policy"), base, token, "/api/v1/policy/check", &body);
}

void DnsApiClient::request(const QString &action, const QString &base, const QString &token,
                           const QByteArray &path, const QJsonObject *body) {
    if (!endpointAllowed(base)) {
        emit requestFailed(action, QStringLiteral("Use trusted HTTPS or a loopback-only HTTP endpoint."));
        return;
    }
    if (token.size() < 16 || token.contains(QLatin1Char('\n')) || token.contains(QLatin1Char('\r'))) {
        emit requestFailed(action, QStringLiteral("Enter a valid API token."));
        return;
    }
    QUrl url(base.trimmed());
    url.setPath(QString::fromLatin1(path));
    url.setQuery(QString());
    url.setFragment(QString());
    QNetworkRequest req(url);
    req.setRawHeader("Authorization", QByteArray("Bearer ") + token.toUtf8());
    req.setRawHeader("Accept", "application/json");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setTransferTimeout(5000);
    QNetworkReply *reply = nullptr;
    if (action == QStringLiteral("status")) {
        reply = network_.get(req);
    } else if (body != nullptr) {
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        reply = network_.post(req, QJsonDocument(*body).toJson(QJsonDocument::Compact));
    } else {
        reply = network_.post(req, QByteArray());
    }
    if (reply == nullptr) {
        emit requestFailed(action, QStringLiteral("Could not start the request."));
        return;
    }

    const quint64 expectedGeneration = generation_;
    requests_.insert(reply);
    auto buffer = std::make_shared<ResponseBuffer>();
    connect(reply, &QIODevice::readyRead, this, [reply, buffer]() {
        if (buffer->exceeded) return;
        const qsizetype room = kMaxResponseBytes + 1 - buffer->bytes.size();
        if (room > 0) buffer->bytes.append(reply->read(room));
        if (buffer->bytes.size() > kMaxResponseBytes || reply->bytesAvailable() > 0) {
            buffer->exceeded = true;
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, buffer, action, expectedGeneration]() {
        requests_.remove(reply);
        const bool stale = expectedGeneration != generation_;
        if (!stale && !buffer->exceeded) {
            buffer->bytes.append(reply->read(kMaxResponseBytes + 1 - buffer->bytes.size()));
            if (buffer->bytes.size() > kMaxResponseBytes || reply->bytesAvailable() > 0) {
                buffer->exceeded = true;
            }
        }
        if (stale) {
            reply->deleteLater();
            return;
        }
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (buffer->exceeded || reply->error() != QNetworkReply::NoError || status != 200) {
            const QString reason = buffer->exceeded
                ? QStringLiteral("Response exceeded the safe size limit.")
                : status >= 300 && status <= 399
                    ? QStringLiteral("Redirect refused to protect API credentials.")
                    : status > 0 ? QStringLiteral("Server returned HTTP %1.").arg(status)
                                 : QStringLiteral("Network or TLS verification failed.");
            emit requestFailed(action, reason);
            reply->deleteLater();
            return;
        }
        QJsonParseError jsonError;
        const QJsonDocument response = QJsonDocument::fromJson(buffer->bytes, &jsonError);
        if (jsonError.error != QJsonParseError::NoError || !response.isObject()) {
            emit requestFailed(action, QStringLiteral("Invalid server JSON response."));
            reply->deleteLater();
            return;
        }
        const QJsonObject data = response.object();
        if (action == QStringLiteral("status")) {
            emit statusReady(data.toVariantMap());
        } else if (action == QStringLiteral("local")) {
            emit localReloaded();
        } else if (action == QStringLiteral("policy")) {
            emit policyReady(data.value(QStringLiteral("name")).toString(),
                             data.value(QStringLiteral("decision")).toString());
        }
        reply->deleteLater();
    });
}
