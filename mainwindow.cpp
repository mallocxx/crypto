#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "crypto.h"
#include <QByteArray>
#include <cstring>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->pushButton, &QPushButton::clicked,
            this, &MainWindow::onUnlockClicked);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onUnlockClicked() {
    QByteArray pass = normalize(ui->lineEdit->text());
    QByteArray container = QByteArray::fromRawData(
        reinterpret_cast<const char*>(kContainer),
        (int)kContainerSize
        );
    QByteArray decrypted = decryptContainer(container, pass);
    if (!decrypted.isEmpty()) {
        ui->label->setText(QString::fromUtf8(decrypted));
        std::memset(decrypted.data(), 0, decrypted.size());
    } else {
        ui->label->setText("ERROR");
    }
    std::memset(pass.data(), 0, pass.size());
}
