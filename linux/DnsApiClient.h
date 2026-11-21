#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QObject>
#include <QSet>
#include <QVariantMap>
#include <QString>
#include <QUrl>

class DnsApiClient final : public QObject {
    Q_OBJECT

public:
    explicit DnsApiClient(QObject *parent = nullptr);
    Q_INVOKABLE bool endpointAllowed(const QString &base) const;
    Q_INVOKABLE void fetchStatus(const QString &base, const QString &token);
    Q_INVOKABLE void reloadLocal(const QString &base, const QString &token);
    Q_INVOKABLE void checkPolicy(const QString &base, const QString &token, const QString &domain);
    Q_INVOKABLE void clearSession();

signals:
    void statusReady(QVariantMap status);
    void policyReady(QString name, QString decision);
    void localReloaded();
    void requestFailed(QString action, QString reason);

private:
    QNetworkAccessManager network_;
    QSet<QNetworkReply *> requests_;
    quint64 generation_ = 0;
    void request(const QString &action, const QString &base, const QString &token,
                 const QByteArray &path, const QJsonObject *body = nullptr);
};
