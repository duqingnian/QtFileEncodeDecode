
#pragma once
#include <QMainWindow>
#include <QThread>
#include <QPointer>

class QLineEdit;
class QPushButton;
class QProgressBar;
class QPlainTextEdit;

class Worker : public QObject {
    Q_OBJECT
public slots:
    void doEncrypt(QString inPath, QString password, QString outPath);
    void doDecrypt(QString inPath, QString password, QString outPath);
signals:
    void progress(qint64 processed, qint64 total);
    void finished(bool ok, QString outPath, QString message);
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
private slots:
    void chooseEncryptFile();
    void chooseDecryptFile();
    void startEncrypt();
    void startDecrypt();
    void onEncryptProgress(qint64, qint64);
    void onDecryptProgress(qint64, qint64);
    void onEncryptFinished(bool ok, const QString& outPath, const QString& msg);
    void onDecryptFinished(bool ok, const QString& outPath, const QString& msg);

private:
    QLineEdit* leEncryptFile{};
    QLineEdit* leEncryptPass{};
    QLineEdit* leDecryptFile{};
    QLineEdit* leDecryptPass{};
    QPushButton* btnChooseEnc{};
    QPushButton* btnChooseDec{};
    QPushButton* btnEncrypt{};
    QPushButton* btnDecrypt{};
    QProgressBar* barEnc{};
    QProgressBar* barDec{};
    QPlainTextEdit* log{};

    QThread* workerThread{};
    QPointer<Worker> worker;
    void appendLog(const QString& s);
};
