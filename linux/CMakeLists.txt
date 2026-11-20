cmake_minimum_required(VERSION 3.25)
project(GoreeCloudDNS VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(Qt6 6.12.0 EXACT REQUIRED COMPONENTS Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.12)
qt_add_executable(goreecloud-dns-linux main.cpp)
qt_add_qml_module(goreecloud-dns-linux
    URI GoreeCloud.DNS
    VERSION 1.0
    QML_FILES Main.qml
)
target_link_libraries(goreecloud-dns-linux PRIVATE Qt6::Quick Qt6::QuickControls2)
install(TARGETS goreecloud-dns-linux RUNTIME DESTINATION bin)
