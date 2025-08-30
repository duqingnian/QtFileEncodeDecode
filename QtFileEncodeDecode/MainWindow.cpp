
#include "MainWindow.h"
#include "Crypto.h"
#include "Version.h"

#include <QApplication>
#include <QWidget>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QProgressBar>
#include <QPlainTextEdit>
#include <QFileInfo>
#include <QMessageBox>

#include <memory>

// ---------------- Worker ----------------

void Worker::doEncrypt(QString inPath, QString password, QString outPath) {
    QString err;
    bool ok = encryptFileWithPassword(inPath, outPath, password,
        [this](qint64 p, qint64 t) { emit progress(p, t); }, err);
    emit finished(ok, outPath, ok ? "加密完成" : err);
}

void Worker::doDecrypt(QString inPath, QString password, QString outPath) {
    QString err;
    bool ok = decryptFileWithPassword(inPath, outPath, password,
        [this](qint64 p, qint64 t) { emit progress(p, t); }, err);
    emit finished(ok, outPath, ok ? "解密完成" : err);
}

// ---------------- MainWindow ----------------

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QString::fromLatin1(AppVer::kAppName));
    auto* cw = new QWidget(this);
    auto* g = new QGridLayout(cw);

    int row = 0;

    // Encrypt section
    g->addWidget(new QLabel("加密输入文件:"), row, 0);
    leEncryptFile = new QLineEdit; g->addWidget(leEncryptFile, row, 1);
    btnChooseEnc = new QPushButton("选择…"); g->addWidget(btnChooseEnc, row, 2);
    row++;

    g->addWidget(new QLabel("加密密码:"), row, 0);
    leEncryptPass = new QLineEdit; leEncryptPass->setEchoMode(QLineEdit::Password);
    g->addWidget(leEncryptPass, row, 1);
    btnEncrypt = new QPushButton("加密"); g->addWidget(btnEncrypt, row, 2);
    row++;

    barEnc = new QProgressBar; barEnc->setRange(0, 100); barEnc->setValue(0);
    g->addWidget(barEnc, row, 0, 1, 3);
    row++;

    // Decrypt section
    g->addWidget(new QLabel("解密输入文件:"), row, 0);
    leDecryptFile = new QLineEdit; g->addWidget(leDecryptFile, row, 1);
    btnChooseDec = new QPushButton("选择…"); g->addWidget(btnChooseDec, row, 2);
    row++;

    g->addWidget(new QLabel("解密密码:"), row, 0);
    leDecryptPass = new QLineEdit; leDecryptPass->setEchoMode(QLineEdit::Password);
    g->addWidget(leDecryptPass, row, 1);
    btnDecrypt = new QPushButton("解密"); g->addWidget(btnDecrypt, row, 2);
    row++;

    barDec = new QProgressBar; barDec->setRange(0, 100); barDec->setValue(0);
    g->addWidget(barDec, row, 0, 1, 3);
    row++;

    // Log
    log = new QPlainTextEdit; log->setReadOnly(true);
    g->addWidget(log, row, 0, 1, 3);
    row++;

    setCentralWidget(cw);

    // Worker thread
    workerThread = new QThread(this);
    worker = new Worker();
    worker->moveToThread(workerThread);
    workerThread->start();

    // Signals
    connect(btnChooseEnc, &QPushButton::clicked, this, &MainWindow::chooseEncryptFile);
    connect(btnChooseDec, &QPushButton::clicked, this, &MainWindow::chooseDecryptFile);
    connect(btnEncrypt, &QPushButton::clicked, this, &MainWindow::startEncrypt);
    connect(btnDecrypt, &QPushButton::clicked, this, &MainWindow::startDecrypt);

    connect(worker, &Worker::progress, this, &MainWindow::onEncryptProgress);
    connect(worker, &Worker::progress, this, &MainWindow::onDecryptProgress);
    // We will switch connections dynamically so progress goes to correct bar.
    // For simplicity we keep both slots; they'll clamp when idle.
    connect(worker, &Worker::finished, this, &MainWindow::onEncryptFinished);
    connect(worker, &Worker::finished, this, &MainWindow::onDecryptFinished);
}

MainWindow::~MainWindow() {
    if (workerThread)
    {
        workerThread->quit();
        workerThread->wait();
        delete worker;
    }
}

void MainWindow::appendLog(const QString& s) {
    log->appendPlainText(s);
}

void MainWindow::chooseEncryptFile() {
    const QString path = QFileDialog::getOpenFileName(this, "选择要加密的文件");
    if (!path.isEmpty()) leEncryptFile->setText(path);
}

void MainWindow::chooseDecryptFile() {
    const QString path = QFileDialog::getOpenFileName(this, "选择要解密的文件");
    if (!path.isEmpty()) leDecryptFile->setText(path);
}

static QString nextAvailablePath(const QString& basePath, const QString& extSuffix) {
    QFileInfo fi(basePath);
    QString dir = fi.absolutePath();
    QString baseName = fi.fileName();
    QString out = basePath + extSuffix;
    int i = 1;
    while (QFileInfo::exists(out))
    {
        out = QString("%1/%2%3.%4").arg(dir).arg(baseName).arg(extSuffix).arg(i++);
    }
    return out;
}

void MainWindow::startEncrypt() {
    const QString inPath = leEncryptFile->text().trimmed();
    const QString pass = leEncryptPass->text();
    if (inPath.isEmpty()) { QMessageBox::warning(this, "提示", "请选择加密输入文件"); return; }
    if (pass.isEmpty()) { QMessageBox::warning(this, "提示", "请输入加密密码"); return; }
    QString outPath = nextAvailablePath(inPath, ".enc");

    btnEncrypt->setEnabled(false);
    btnDecrypt->setEnabled(false);
    barEnc->setValue(0);
    appendLog(QString("[加密] 输入: %1").arg(inPath));
    appendLog(QString("[加密] 输出: %1").arg(outPath));

    // Disconnect to avoid duplicated progress routing
    disconnect(worker, &Worker::progress, this, &MainWindow::onDecryptProgress);
    connect(worker, &Worker::progress, this, &MainWindow::onEncryptProgress, Qt::UniqueConnection);
    disconnect(worker, &Worker::finished, this, &MainWindow::onDecryptFinished);
    connect(worker, &Worker::finished, this, &MainWindow::onEncryptFinished, Qt::UniqueConnection);

    QMetaObject::invokeMethod(worker, "doEncrypt", Qt::QueuedConnection,
        Q_ARG(QString, inPath),
        Q_ARG(QString, pass),
        Q_ARG(QString, outPath));
}

void MainWindow::startDecrypt() {
    const QString inPath = leDecryptFile->text().trimmed();
    const QString pass = leDecryptPass->text();
    if (inPath.isEmpty()) { QMessageBox::warning(this, "提示", "请选择解密输入文件"); return; }
    if (pass.isEmpty()) { QMessageBox::warning(this, "提示", "请输入解密密码"); return; }

    QString base = inPath;
    if (base.endsWith(".enc")) base = base.left(base.size() - 4);
    QString outPath = nextAvailablePath(base, ".dec");

    btnEncrypt->setEnabled(false);
    btnDecrypt->setEnabled(false);
    barDec->setValue(0);
    appendLog(QString("[解密] 输入: %1").arg(inPath));
    appendLog(QString("[解密] 输出: %1").arg(outPath));

    // Route progress/finished to decrypt handlers
    disconnect(worker, &Worker::progress, this, &MainWindow::onEncryptProgress);
    connect(worker, &Worker::progress, this, &MainWindow::onDecryptProgress, Qt::UniqueConnection);
    disconnect(worker, &Worker::finished, this, &MainWindow::onEncryptFinished);
    connect(worker, &Worker::finished, this, &MainWindow::onDecryptFinished, Qt::UniqueConnection);

    QMetaObject::invokeMethod(worker, "doDecrypt", Qt::QueuedConnection,
        Q_ARG(QString, inPath),
        Q_ARG(QString, pass),
        Q_ARG(QString, outPath));
}

void MainWindow::onEncryptProgress(qint64 p, qint64 t) {
    if (t <= 0) return;
    int v = static_cast<int>(p * 100 / t);
    barEnc->setValue(std::clamp(v, 0, 100));
}

void MainWindow::onDecryptProgress(qint64 p, qint64 t) {
    if (t <= 0) return;
    int v = static_cast<int>(p * 100 / t);
    barDec->setValue(std::clamp(v, 0, 100));
}

void MainWindow::onEncryptFinished(bool ok, const QString& outPath, const QString& msg) {
    btnEncrypt->setEnabled(true);
    btnDecrypt->setEnabled(true);
    appendLog(ok ? QString("[加密完成] 输出: %1").arg(outPath)
        : QString("[加密失败] %1").arg(msg));
    if (!ok) QMessageBox::critical(this, "错误", msg);
}

void MainWindow::onDecryptFinished(bool ok, const QString& outPath, const QString& msg) {
    btnEncrypt->setEnabled(true);
    btnDecrypt->setEnabled(true);
    appendLog(ok ? QString("[解密完成] 输出: %1").arg(outPath)
        : QString("[解密失败] %1").arg(msg));
    if (!ok) QMessageBox::critical(this, "错误", msg);
}
