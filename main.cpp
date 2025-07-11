#include <QApplication>
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QStyleFactory>
#include <QFont>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <QByteArray>
#include <QMessageBox>
#include <QRegularExpression>

const QByteArray salt = "unique_romantic_salt_18.12.2024";
const QByteArray secret_append = "s3cr3t!";

QByteArray encryptMessage(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv_out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    QByteArray iv(12, 0);
    RAND_bytes(reinterpret_cast<unsigned char *>(iv.data()), iv.size());
    iv_out = iv;
    QByteArray ciphertext(plaintext.size() + 16, 0);
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                       reinterpret_cast<const unsigned char *>(key.data()),
                       reinterpret_cast<const unsigned char *>(iv.data()));

    EVP_EncryptUpdate(ctx,
                      reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
                      reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size());

    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + len, &len);
    ciphertext_len += len;

    QByteArray tag(16, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return iv + ciphertext.left(ciphertext_len) + tag;
}

QByteArray deriveKey(const QString &password)
{
    QByteArray pass = password.toUtf8() + secret_append;
    QByteArray key(32, 0);
    PKCS5_PBKDF2_HMAC(pass.data(), pass.size(),
                      reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
                      500000, EVP_sha256(),
                      key.size(), reinterpret_cast<unsigned char *>(key.data()));
    return key;
}

QByteArray decryptMessage(const QByteArray &ciphertext, const QByteArray &key)
{
    if (ciphertext.size() < 12 + 16)
        return QByteArray();
    QByteArray iv = ciphertext.left(12);
    QByteArray tag = ciphertext.right(16);
    QByteArray encrypted = ciphertext.mid(12, ciphertext.size() - 12 - 16);
    QByteArray plaintext(encrypted.size(), 0);
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                       reinterpret_cast<const unsigned char *>(key.data()),
                       reinterpret_cast<const unsigned char *>(iv.data()));
    EVP_DecryptUpdate(ctx,
                      reinterpret_cast<unsigned char *>(plaintext.data()), &len,
                      reinterpret_cast<const unsigned char *>(encrypted.data()), encrypted.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(tag.data())));

    int ret = EVP_DecryptFinal_ex(ctx, NULL, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        return plaintext;
    }
    else
    {
        return QByteArray();
    }
}

QString normalize(const QString &s)
{
    return s.trimmed().toLower().replace(QRegularExpression("\\s+"), " ");
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(30, 30, 30));
    darkPalette.setColor(QPalette::WindowText, Qt::white);
    darkPalette.setColor(QPalette::Base, QColor(255, 255, 255));
    darkPalette.setColor(QPalette::AlternateBase, QColor(50, 50, 50));
    darkPalette.setColor(QPalette::Text, QColor(30, 30, 30));
    darkPalette.setColor(QPalette::Button, QColor(60, 60, 60));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);
    darkPalette.setColor(QPalette::Highlight, QColor(100, 100, 150));
    darkPalette.setColor(QPalette::HighlightedText, Qt::white);

    app.setPalette(darkPalette);

    QWidget window;
    window.setWindowTitle("что это тут у нас");

    QVBoxLayout *layout = new QVBoxLayout(&window);
    layout->setAlignment(Qt::AlignVCenter);
    layout->setSpacing(15);

    QLineEdit *lineEdit = new QLineEdit;
    lineEdit->setMinimumHeight(45);
    lineEdit->setFont(QFont("Sans Serif", 14));
    lineEdit->setPlaceholderText("Введите пароль");

    QPushButton *button = new QPushButton("Открыть");
    button->setMinimumHeight(45);
    button->setFixedWidth(140);
    button->setFont(QFont("Sans Serif", 14));

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addStretch();
    buttonLayout->addWidget(button);
    buttonLayout->addStretch();

    QLabel *label = new QLabel;
    label->setWordWrap(true);
    label->setFont(QFont("Sans Serif", 14));
    label->setAlignment(Qt::AlignCenter);

    lineEdit->setStyleSheet(
        "QLineEdit {"
        "background-color: #262626;"
        "border: 1px solid #121212;"
        "border-radius: 10px;"
        "padding: 8px;"
        "color: white;"
        "}");

    button->setStyleSheet(
        "QPushButton {"
        "background-color: #262626;"
        "color: white;"
        "border: 1px solid #121212;"
        "border-radius: 10px;"
        "padding: 10px 20px;"
        "}"
        "QPushButton:hover {"
        "background-color: #333333;"
        "}"
        "QPushButton:pressed {"
        "background-color: #262626;"
        "}");

    layout->addWidget(lineEdit);
    layout->addLayout(buttonLayout);
    layout->addWidget(label);

    QString confession = "я тебя тоже";
    QString confession3 = "i love you too";
    QByteArray key = deriveKey("я люблю тебя");
    QByteArray key2 = deriveKey("я тебя люблю");
    QByteArray key3 = deriveKey("i love you");
    QByteArray key4 = deriveKey("люблю тебя");
    QByteArray iv_out;
    QByteArray encrypted = encryptMessage(confession.toUtf8(), key, iv_out);
    QByteArray encrypted2 = encryptMessage(confession.toUtf8(), key2, iv_out);
    QByteArray encrypted3 = encryptMessage(confession3.toUtf8(), key3, iv_out);
    QByteArray encrypted4 = encryptMessage(confession.toUtf8(), key4, iv_out);

    QObject::connect(button, &QPushButton::clicked, [&]()
                     {
                         QByteArray enteredKey = deriveKey(normalize(lineEdit->text()));
                         QByteArray decrypted = decryptMessage(encrypted, enteredKey);
                         QByteArray decrypted2 = decryptMessage(encrypted2, enteredKey);
                         QByteArray decrypted3 = decryptMessage(encrypted3, enteredKey);
                         QByteArray decrypted4 = decryptMessage(encrypted4, enteredKey);
                         if (!decrypted.isEmpty()) {
                             label->setText(QString::fromUtf8(decrypted));
                         } else if (!decrypted2.isEmpty()) {
                             label->setText(QString::fromUtf8(decrypted2));
                         } else if (!decrypted3.isEmpty()) {
                             label->setText(QString::fromUtf8(decrypted3));
                         } else if (!decrypted4.isEmpty()) {
                             label->setText(QString::fromUtf8(decrypted4));
                         } else {
                             label->setText("Неверный пароль.");
                         } });

    window.resize(600, 350);
    window.show();
    return app.exec();
}
