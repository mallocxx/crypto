QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    crypto.cpp \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    crypto.h \
    mainwindow.h

FORMS += \
    mainwindow.ui

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

QT += core gui widgets

CONFIG += c++17

unix: LIBS += -lssl -lcrypto -lsodium

QMAKE_CXXFLAGS += -fPIC
