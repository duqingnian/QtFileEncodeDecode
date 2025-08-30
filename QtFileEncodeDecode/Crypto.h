
#pragma once
#include <QString>
#include <QByteArray>
#include <functional>

// 进度回调：processed / total
using ProgressFn = std::function<void(qint64, qint64)>;

// 返回 true 表示成功；失败时 errorMsg 填充描述。
bool encryptFileWithPassword(const QString& inPath, const QString& outPath, const QString& password,
                             const ProgressFn& progress, QString& errorMsg);

bool decryptFileWithPassword(const QString& inPath, const QString& outPath, const QString& password,
                             const ProgressFn& progress, QString& errorMsg);
