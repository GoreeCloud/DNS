#include "DnsApiClient.h"
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QString>

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    DnsApiClient dnsApi;
    // Offline, deterministic endpoint validation for CI and operator preflight.
    if (argc == 3 && QString::fromUtf8(argv[1]) == QStringLiteral("--validate-endpoint")) {
        return dnsApi.endpointAllowed(QString::fromUtf8(argv[2])) ? 0 : 2;
    }
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("dnsApi", &dnsApi);
    engine.loadFromModule("GoreeCloud.DNS", "Main");
    if (engine.rootObjects().isEmpty()) return 1;
    return app.exec();
}
