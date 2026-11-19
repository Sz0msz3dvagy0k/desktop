/*
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "clientsideencryption.h"
#include "clientsideencryptionjobs.h"
#include "common/syncjournaldb.h"
#include "foldermetadata.h"
#include "syncenginetestutils.h"
#include <QtTest>

using namespace OCC;
using namespace Qt::StringLiterals;

class TestClientSideEncryptionV2 : public QObject
{
    Q_OBJECT

    QScopedPointer<FakeQNAM> _fakeQnam;
    QScopedPointer<FolderMetadata> _parsedMetadataWithFileDrop;
    QScopedPointer<FolderMetadata> _parsedMetadataAfterProcessingFileDrop;

    AccountPtr _account;
    AccountPtr _secondAccount;

private Q_SLOTS:
    void initTestCase()
    {
        OCC::Logger::instance()->setLogFlush(true);
        OCC::Logger::instance()->setLogDebug(true);

        QStandardPaths::setTestModeEnabled(true);

        QVariantMap fakeCapabilities;
        fakeCapabilities[QStringLiteral("end-to-end-encryption")] = QVariantMap{
            {QStringLiteral("enabled"), true},
            {QStringLiteral("api-version"), "2.0"}
        };
        const QUrl fakeUrl("http://example.de");

        {
            _account = Account::create();
            _fakeQnam.reset(new FakeQNAM({}));
            const auto cred = new FakeCredentials{_fakeQnam.data()};
            cred->setUserName("test");
            _account->setCredentials(cred);
            _account->setUrl(fakeUrl);
            _account->setCapabilities(fakeCapabilities);
        }
        {
            // make a second fake account so we can share metadata to it later
            _secondAccount = Account::create();
            _fakeQnam.reset(new FakeQNAM({}));
            const auto credSecond = new FakeCredentials{_fakeQnam.data()};
            credSecond->setUserName("sharee");
            _secondAccount->setCredentials(credSecond);
            _secondAccount->setUrl(fakeUrl);
            _secondAccount->setCapabilities(fakeCapabilities);        
        }

        QSslCertificate cert;
        QSslKey publicKey;
        QByteArray privateKey;

        {
            QFile e2eTestFakeCert(QStringLiteral("e2etestsfakecert.pem"));
            QVERIFY(e2eTestFakeCert.open(QFile::ReadOnly));
            cert = QSslCertificate(e2eTestFakeCert.readAll());
        }
        {
            QFile e2etestsfakecertpublickey(QStringLiteral("e2etestsfakecertpublickey.pem"));
            QVERIFY(e2etestsfakecertpublickey.open(QFile::ReadOnly));
            publicKey = QSslKey(e2etestsfakecertpublickey.readAll(), QSsl::KeyAlgorithm::Rsa, QSsl::EncodingFormat::Pem, QSsl::KeyType::PublicKey);
            e2etestsfakecertpublickey.close();
        }
        {
            QFile e2etestsfakecertprivatekey(QStringLiteral("e2etestsfakecertprivatekey.pem"));
            QVERIFY(e2etestsfakecertprivatekey.open(QFile::ReadOnly));
            privateKey = e2etestsfakecertprivatekey.readAll();
        }

        QVERIFY(!cert.isNull());
        QVERIFY(!publicKey.isNull());
        QVERIFY(!privateKey.isEmpty());

        _account->e2e()->setCertificate(cert);
        _account->e2e()->setPrivateKey(privateKey);

        _secondAccount->e2e()->setCertificate(cert);
        _secondAccount->e2e()->setPrivateKey(privateKey);
        QVERIFY(QMetaObject::invokeMethod(_secondAccount->e2e(), "setMnemonic", Qt::DirectConnection, Q_ARG(QString, u"test mnemonic"_s)));
    }

    void testInitializeNewRootFolderMetadataThenEncryptAndDecrypt()
    {
        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        const auto fakeFileName = "fakefile.txt";

        FolderMetadata::EncryptedFile encryptedFile;
        encryptedFile.encryptionKey = EncryptionHelper::generateRandom(16);
        encryptedFile.encryptedFilename = EncryptionHelper::generateRandomFilename();
        encryptedFile.originalFilename = fakeFileName;
        encryptedFile.mimetype = "application/octet-stream";
        encryptedFile.initializationVector = EncryptionHelper::generateRandom(16);
        QVERIFY(metadata->addEncryptedFile(encryptedFile));

        const auto encryptedMetadata = metadata->encryptedMetadata();
        QVERIFY(!encryptedMetadata.isEmpty());

        const auto signature = metadata->metadataSignature();
        QVERIFY(!signature.isEmpty());

        const auto metaDataDoc = QJsonDocument::fromJson(encryptedMetadata);
        const auto folderUsers = metaDataDoc["users"].toArray();
        QVERIFY(!folderUsers.isEmpty());

        auto isCurrentUserPresentAndCanDecrypt = false;
        for (auto it = folderUsers.constBegin(); it != folderUsers.constEnd(); ++it) {
            const auto folderUserObject = it->toObject();
            const auto userId = folderUserObject.value("userId").toString();

            if (userId != _account->davUser()) {
                continue;
            }

            const auto certificatePem = folderUserObject.value("certificate").toString().toUtf8();
            const auto certificate = QSslCertificate{certificatePem};
            const auto encryptedMetadataKey = QByteArray::fromBase64(folderUserObject.value("encryptedMetadataKey").toString().toUtf8());

            if (!encryptedMetadataKey.isEmpty()) {
                const auto decryptedMetadataKey = metadata->decryptDataWithPrivateKey(encryptedMetadataKey, _account->e2e()->certificateSha256Fingerprint());
                if (decryptedMetadataKey.isEmpty()) {
                    break;
                }
                
                const auto metadataObj = metaDataDoc.object()["metadata"].toObject();

                const auto cipherTextEncrypted = metadataObj["ciphertext"].toString().toLocal8Bit();

                // for compatibility, the format is "cipheredpart|initializationVector", so we need to extract the "cipheredpart"
                const auto cipherTextPartExtracted = cipherTextEncrypted.split('|').at(0);

                const auto nonce = QByteArray::fromBase64(metadataObj["nonce"].toString().toLocal8Bit());

                const auto cipherTextDecrypted =
                    EncryptionHelper::decryptThenUnGzipData(decryptedMetadataKey, QByteArray::fromBase64(cipherTextPartExtracted), nonce);
                if (cipherTextDecrypted.isEmpty()) {
                    break;
                }

                const auto cipherTextDocument = QJsonDocument::fromJson(cipherTextDecrypted);
                const auto files = cipherTextDocument.object()["files"].toObject();

                if (files.isEmpty()) {
                    break;
                }

                const auto parsedEncryptedFile = metadata->parseEncryptedFileFromJson(files.keys().first(), files.value(files.keys().first()));

                QCOMPARE(parsedEncryptedFile.originalFilename, fakeFileName);

                isCurrentUserPresentAndCanDecrypt = true;
                break;
            }
        }
        QEXPECT_FAIL("", "to be fixed later or removed entirely", Continue);
        QVERIFY(isCurrentUserPresentAndCanDecrypt);

        auto encryptedMetadataCopy = encryptedMetadata;
        encryptedMetadataCopy.replace("\"", "\\\""); 

        QJsonDocument ocsDoc = QJsonDocument::fromJson(QStringLiteral("{\"ocs\": {\"data\": {\"meta-data\": \"%1\"}}}").arg(QString::fromUtf8(encryptedMetadataCopy)).toUtf8());
        

        QScopedPointer<FolderMetadata> metadataFromJson(new FolderMetadata(_account, "/",
            ocsDoc.toJson(),
            RootEncryptedFolderInfo::makeDefault(), signature, FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupExistingCompleteSpy(metadataFromJson.data(), &FolderMetadata::setupComplete);
        metadataSetupExistingCompleteSpy.wait();
        QCOMPARE(metadataSetupExistingCompleteSpy.count(), 1);
        QEXPECT_FAIL("", "to be fixed later or removed entirely", Continue);
        QVERIFY(metadataFromJson->isValid());
    }

    void testFolderMetadataWithEmptySignatureDecryptFails()
    {
        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        const auto encryptedMetadata = metadata->encryptedMetadata();
        QVERIFY(!encryptedMetadata.isEmpty());

        const auto signature = metadata->metadataSignature();
        QVERIFY(!signature.isEmpty());

        auto encryptedMetadataCopy = encryptedMetadata;
        encryptedMetadataCopy.replace("\"", "\\\"");

        const QJsonDocument ocsDoc = QJsonDocument::fromJson(QStringLiteral("{\"ocs\": {\"data\": {\"meta-data\": \"%1\"}}}")
                                                           .arg(QString::fromUtf8(encryptedMetadataCopy)).toUtf8());

        const QByteArray emptySignature = {};
        QScopedPointer<FolderMetadata> metadataFromJson(new FolderMetadata(_account, "/",
                                                                           ocsDoc.toJson(),
                                                                           RootEncryptedFolderInfo::makeDefault(),
                                                                           emptySignature,
                                                                           FolderMetadata::FolderType::Root));

        QSignalSpy metadataSetupExistingCompleteSpy(metadataFromJson.data(), &FolderMetadata::setupComplete);
        metadataSetupExistingCompleteSpy.wait();
        QCOMPARE(metadataSetupExistingCompleteSpy.count(), 1);

        QVERIFY(metadataFromJson->metadataSignature().isEmpty());
        QVERIFY(metadataFromJson->binaryMetadataKeyForDecryption().isEmpty());
        QVERIFY(!metadataFromJson->isValid());
    }

    void testUnlockTokenPersistence_data()
    {
        QTest::addColumn<int>("httpStatus");
        QTest::addColumn<bool>("tokenShouldRemain");

        QTest::newRow("success") << 200 << false;
        QTest::newRow("already-unlocked") << 404 << false;
        QTest::newRow("network-error") << 0 << true;
        QTest::newRow("forbidden") << 403 << true;
        QTest::newRow("server-error") << 500 << true;
    }

    void testUnlockTokenPersistence()
    {
        QFETCH(int, httpStatus);
        QFETCH(bool, tokenShouldRemain);

        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        const auto folderId = "encrypted-folder-id"_ba;
        const auto rawToken = "raw-lock-token"_ba;
        const auto encryptedToken = "encrypted-lock-token"_ba;
        SyncJournalDb journal(temporaryDirectory.filePath(u"journal.db"_s));
        journal.setE2EeLockedFolder(folderId, encryptedToken);

        auto requestSeen = false;
        _fakeQnam->setOverride(
            [this, httpStatus, &requestSeen](const QNetworkAccessManager::Operation operation, const QNetworkRequest &request, QIODevice *) -> QNetworkReply * {
                if (operation != QNetworkAccessManager::DeleteOperation) {
                    return nullptr;
                }

                requestSeen = true;
                if (httpStatus == 200) {
                    return new FakeJsonReply(operation, request, _fakeQnam.data(), httpStatus);
                }
                return new FakeErrorReply(operation, request, _fakeQnam.data(), httpStatus);
            });

        auto unlockJob = new UnlockEncryptFolderApiJob(_secondAccount, folderId, rawToken, &journal, this);
        QSignalSpy doneSpy(unlockJob, &UnlockEncryptFolderApiJob::done);
        unlockJob->start();

        QVERIFY(doneSpy.wait());
        QVERIFY(requestSeen);
        QCOMPARE(!journal.e2EeLockedFolder(folderId).isEmpty(), tokenShouldRemain);

        _fakeQnam->setOverride({});
    }

    void testStaleUnlockDoesNotDeleteNewToken()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        const auto folderId = "encrypted-folder-id"_ba;
        const auto oldEncryptedToken = "old-encrypted-lock-token"_ba;
        const auto newEncryptedToken = "new-encrypted-lock-token"_ba;
        SyncJournalDb journal(temporaryDirectory.filePath(u"journal.db"_s));
        journal.setE2EeLockedFolder(folderId, oldEncryptedToken);

        _fakeQnam->setOverride([this](const QNetworkAccessManager::Operation operation, const QNetworkRequest &request, QIODevice *) -> QNetworkReply * {
            if (operation == QNetworkAccessManager::DeleteOperation) {
                return new FakeJsonReply(operation, request, _fakeQnam.data(), 200);
            }
            return nullptr;
        });

        auto unlockJob = new UnlockEncryptFolderApiJob(_secondAccount, folderId, "old-raw-lock-token"_ba, &journal, this);
        QSignalSpy doneSpy(unlockJob, &UnlockEncryptFolderApiJob::done);
        unlockJob->start();
        journal.setE2EeLockedFolder(folderId, newEncryptedToken);

        const auto doneReceived = doneSpy.wait();
        _fakeQnam->setOverride({});

        QVERIFY(doneReceived);
        QCOMPARE(journal.e2EeLockedFolder(folderId), newEncryptedToken);
    }

    void testLockRecoveryStopsAfterFailedUnlock()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        const auto folderId = "encrypted-folder-id"_ba;
        const auto rawToken = "raw-lock-token"_ba;
        const auto encryptedToken = EncryptionHelper::encryptStringAsymmetric(_secondAccount->e2e()->getCertificateInformation(),
                                                                              _secondAccount->e2e()->paddingMode(),
                                                                              *_secondAccount->e2e(),
                                                                              rawToken);
        QVERIFY(encryptedToken.has_value());

        SyncJournalDb journal(temporaryDirectory.filePath(u"journal.db"_s));
        journal.setE2EeLockedFolder(folderId, *encryptedToken);

        auto deleteRequestCount = 0;
        auto postRequestCount = 0;
        auto sentUnlockToken = QByteArray{};
        _fakeQnam->setOverride([this, &deleteRequestCount, &postRequestCount, &sentUnlockToken](const QNetworkAccessManager::Operation operation,
                                                                                                const QNetworkRequest &request,
                                                                                                QIODevice *) -> QNetworkReply * {
            if (operation == QNetworkAccessManager::DeleteOperation) {
                ++deleteRequestCount;
                sentUnlockToken = request.rawHeader("e2e-token");
                return new FakeErrorReply(operation, request, _fakeQnam.data(), 403);
            }
            if (operation == QNetworkAccessManager::PostOperation) {
                ++postRequestCount;
            }
            return nullptr;
        });

        auto lockJob = new LockEncryptFolderApiJob(_secondAccount, folderId, _secondAccount->e2e()->certificateSha256Fingerprint(), &journal, {}, this);
        QSignalSpy errorSpy(lockJob, &LockEncryptFolderApiJob::error);
        lockJob->start();

        const auto errorReceived = errorSpy.wait();
        _fakeQnam->setOverride({});

        QVERIFY(errorReceived);
        QCOMPARE(deleteRequestCount, 1);
        QCOMPARE(postRequestCount, 0);
        QCOMPARE(sentUnlockToken, rawToken);
        QCOMPARE(journal.e2EeLockedFolder(folderId), *encryptedToken);
    }

    void testLockRecoveryReportsStoredTokenDecryptionFailure()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        const auto folderId = "encrypted-folder-id"_ba;
        const auto invalidEncryptedToken = "not-an-encrypted-lock-token"_ba;
        SyncJournalDb journal(temporaryDirectory.filePath(u"journal.db"_s));
        journal.setE2EeLockedFolder(folderId, invalidEncryptedToken);

        auto requestCount = 0;
        _fakeQnam->setOverride([&requestCount](QNetworkAccessManager::Operation, const QNetworkRequest &, QIODevice *) -> QNetworkReply * {
            ++requestCount;
            return nullptr;
        });

        auto lockJob = new LockEncryptFolderApiJob(_secondAccount, folderId, _secondAccount->e2e()->certificateSha256Fingerprint(), &journal, {}, this);
        QSignalSpy errorSpy(lockJob, &LockEncryptFolderApiJob::error);
        lockJob->start();

        _fakeQnam->setOverride({});

        QCOMPARE(errorSpy.count(), 1);
        QCOMPARE(errorSpy.constFirst().at(0).toByteArray(), folderId);
        QCOMPARE(errorSpy.constFirst().at(1).toInt(), 0);
        QVERIFY(!errorSpy.constFirst().at(2).toString().isEmpty());
        QCOMPARE(requestCount, 0);
        QCOMPARE(journal.e2EeLockedFolder(folderId), invalidEncryptedToken);
    }

    void testLockRecoveryContinuesWhenServerAlreadyUnlocked()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        const auto folderId = "encrypted-folder-id"_ba;
        const auto oldRawToken = "old-raw-lock-token"_ba;
        const auto newRawToken = "new-raw-lock-token"_ba;
        const auto encryptedToken = EncryptionHelper::encryptStringAsymmetric(_secondAccount->e2e()->getCertificateInformation(),
                                                                              _secondAccount->e2e()->paddingMode(),
                                                                              *_secondAccount->e2e(),
                                                                              oldRawToken);
        QVERIFY(encryptedToken.has_value());

        SyncJournalDb journal(temporaryDirectory.filePath(u"journal.db"_s));
        journal.setE2EeLockedFolder(folderId, *encryptedToken);

        const auto lockResponse = QJsonDocument::fromJson(R"({"ocs":{"data":{"e2e-token":"new-raw-lock-token"}}})");
        auto deleteRequestCount = 0;
        auto postRequestCount = 0;
        auto sentUnlockToken = QByteArray{};
        _fakeQnam->setOverride([this, &deleteRequestCount, &postRequestCount, &lockResponse, &sentUnlockToken](const QNetworkAccessManager::Operation operation,
                                                                                                               const QNetworkRequest &request,
                                                                                                               QIODevice *) -> QNetworkReply * {
            if (operation == QNetworkAccessManager::DeleteOperation) {
                ++deleteRequestCount;
                sentUnlockToken = request.rawHeader("e2e-token");
                return new FakeErrorReply(operation, request, _fakeQnam.data(), 404);
            }
            if (operation == QNetworkAccessManager::PostOperation) {
                ++postRequestCount;
                return new FakeJsonReply(operation, request, _fakeQnam.data(), 200, lockResponse);
            }
            return nullptr;
        });

        auto lockJob = new LockEncryptFolderApiJob(_secondAccount, folderId, _secondAccount->e2e()->certificateSha256Fingerprint(), &journal, {}, this);
        QSignalSpy successSpy(lockJob, &LockEncryptFolderApiJob::success);
        lockJob->start();

        const auto successReceived = successSpy.wait();
        _fakeQnam->setOverride({});

        QVERIFY(successReceived);
        QCOMPARE(deleteRequestCount, 1);
        QCOMPARE(postRequestCount, 1);
        QCOMPARE(sentUnlockToken, oldRawToken);
        const auto persistedToken = journal.e2EeLockedFolder(folderId);
        QVERIFY(!persistedToken.isEmpty());
        const auto decryptedToken = EncryptionHelper::decryptStringAsymmetric(_secondAccount->e2e()->getCertificateInformation(),
                                                                              _secondAccount->e2e()->paddingMode(),
                                                                              *_secondAccount->e2e(),
                                                                              persistedToken);
        QVERIFY(decryptedToken.has_value());
        QCOMPARE(QByteArray::fromBase64(*decryptedToken), newRawToken);
    }

    void testOriginalFilenameValidation_data()
    {
        QTest::addColumn<QString>("originalFilename");
        QTest::addColumn<bool>("isValid");

        QTest::newRow("plain file") << QStringLiteral("document.txt") << true;
        QTest::newRow("plain folder") << QStringLiteral("Documents") << true;
        QTest::newRow("hidden file") << QStringLiteral(".hidden") << true;
        QTest::newRow("empty") << QString() << false;
        QTest::newRow("current directory") << QStringLiteral(".") << false;
        QTest::newRow("parent directory") << QStringLiteral("..") << false;
        QTest::newRow("relative traversal") << QStringLiteral("../../poc_dir") << false;
        QTest::newRow("embedded slash") << QStringLiteral("folder/file.txt") << false;
        QTest::newRow("absolute path") << QStringLiteral("/tmp/poc") << false;
        QTest::newRow("backslash") << QStringLiteral("folder\\file.txt") << false;
        QTest::newRow("null byte") << QStringLiteral("file") + QChar(0) + QStringLiteral("name") << false;
    }

    void testOriginalFilenameValidation()
    {
        QFETCH(QString, originalFilename);
        QFETCH(bool, isValid);

        QCOMPARE(FolderMetadata::isOriginalFilenameValid(originalFilename), isValid);
    }

    void testParseEncryptedFileFromJsonRejectsUnsafeOriginalFilename_data()
    {
        testOriginalFilenameValidation_data();
    }

    void testParseEncryptedFileFromJsonRejectsUnsafeOriginalFilename()
    {
        QFETCH(QString, originalFilename);
        QFETCH(bool, isValid);

        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        const auto fileJson = QJsonObject{
            {QStringLiteral("filename"), originalFilename},
            {QStringLiteral("key"), QString::fromUtf8(QByteArrayLiteral("key").toBase64())},
            {QStringLiteral("mimetype"), QStringLiteral("application/octet-stream")},
            {QStringLiteral("nonce"), QString::fromUtf8(QByteArrayLiteral("nonce").toBase64())},
            {QStringLiteral("authenticationTag"), QString::fromUtf8(QByteArrayLiteral("tag").toBase64())},
        };

        const auto parsedEncryptedFile = metadata->parseEncryptedFileFromJson(QStringLiteral("encrypted-name"), fileJson);
        QCOMPARE(!parsedEncryptedFile.originalFilename.isEmpty(), isValid);
        if (isValid) {
            QCOMPARE(parsedEncryptedFile.originalFilename, originalFilename);
        }
    }

    void testAddEncryptedFileRejectsUnsafeOriginalFilename()
    {
        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        FolderMetadata::EncryptedFile encryptedFile;
        encryptedFile.encryptionKey = EncryptionHelper::generateRandom(16);
        encryptedFile.encryptedFilename = EncryptionHelper::generateRandomFilename();
        encryptedFile.originalFilename = QStringLiteral("folder\\file.txt");
        encryptedFile.mimetype = "application/octet-stream";
        encryptedFile.initializationVector = EncryptionHelper::generateRandom(16);

        QVERIFY(!metadata->addEncryptedFile(encryptedFile));
        QVERIFY(metadata->files().isEmpty());
    }

    void testSetupExistingMetadataRejectsUnsafeOriginalFilename()
    {
        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        const auto initialEncryptedMetadata = metadata->encryptedMetadata();
        QVERIFY(!initialEncryptedMetadata.isEmpty());

        const auto encryptedFilename = QStringLiteral("encrypted-name");
        const auto fileJson = QJsonObject{
            {QStringLiteral("filename"), QStringLiteral("folder\\file.txt")},
            {QStringLiteral("key"), QString::fromUtf8(EncryptionHelper::generateRandom(16).toBase64())},
            {QStringLiteral("mimetype"), QStringLiteral("application/octet-stream")},
            {QStringLiteral("nonce"), QString::fromUtf8(EncryptionHelper::generateRandom(16).toBase64())},
            {QStringLiteral("authenticationTag"), QString::fromUtf8(EncryptionHelper::generateRandom(16).toBase64())},
        };

        QJsonArray keyChecksums;
        for (auto it = metadata->_keyChecksums.constBegin(), end = metadata->_keyChecksums.constEnd(); it != end; ++it) {
            keyChecksums.push_back(QJsonValue::fromVariant(*it));
        }

        const auto cipherText = QJsonObject{
            {QStringLiteral("counter"), QJsonValue::fromVariant(metadata->newCounter())},
            {QStringLiteral("files"), QJsonObject{{encryptedFilename, fileJson}}},
            {QStringLiteral("folders"), QJsonObject{}},
            {QStringLiteral("keyChecksums"), keyChecksums},
        };
        const auto cipherTextDoc = QJsonDocument(cipherText);

        QByteArray authenticationTag;
        const auto nonce = EncryptionHelper::generateRandom(16);
        const auto encryptedCipherText = EncryptionHelper::gzipThenEncryptData(metadata->binaryMetadataKeyForEncryption(),
                                                                               cipherTextDoc.toJson(QJsonDocument::Compact),
                                                                               nonce,
                                                                               authenticationTag).toBase64()
            + QByteArrayLiteral("|") + nonce.toBase64();

        auto metadataDoc = QJsonDocument::fromJson(initialEncryptedMetadata);
        auto metaObject = metadataDoc.object();
        auto metadataObject = metaObject[QStringLiteral("metadata")].toObject();
        metadataObject.insert(QStringLiteral("ciphertext"), QString::fromUtf8(encryptedCipherText));
        metadataObject.insert(QStringLiteral("nonce"), QString::fromUtf8(nonce.toBase64()));
        metadataObject.insert(QStringLiteral("authenticationTag"), QString::fromUtf8(authenticationTag.toBase64()));
        metaObject.insert(QStringLiteral("metadata"), metadataObject);
        metadataDoc.setObject(metaObject);

        const auto signature = _account->e2e()->generateSignatureCryptographicMessageSyntax(FolderMetadata::prepareMetadataForSignature(metadataDoc).toBase64()).toBase64();
        QVERIFY(!signature.isEmpty());

        const auto ocsDoc = QJsonDocument(QJsonObject{
            {QStringLiteral("ocs"), QJsonObject{
                {QStringLiteral("data"), QJsonObject{
                    {QStringLiteral("meta-data"), QString::fromUtf8(metadataDoc.toJson(QJsonDocument::Compact))},
                }},
            }},
        });

        QScopedPointer<FolderMetadata> metadataFromJson(new FolderMetadata(_account,
                                                                           "/",
                                                                           ocsDoc.toJson(),
                                                                           RootEncryptedFolderInfo::makeDefault(),
                                                                           signature,
                                                                           FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupExistingCompleteSpy(metadataFromJson.data(), &FolderMetadata::setupComplete);
        metadataSetupExistingCompleteSpy.wait();
        QCOMPARE(metadataSetupExistingCompleteSpy.count(), 1);
        QVERIFY(!metadataFromJson->isValid());
        QVERIFY(metadataFromJson->files().isEmpty());
    }

    void testE2EeFolderMetadataSharing()
    {
        // instantiate empty metadata, add a file, and share with a second user "sharee"
        QScopedPointer<FolderMetadata> metadata(new FolderMetadata(_account, "/", FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupCompleteSpy(metadata.data(), &FolderMetadata::setupComplete);
        metadataSetupCompleteSpy.wait();
        QCOMPARE(metadataSetupCompleteSpy.count(), 1);
        QVERIFY(metadata->isValid());

        const auto fakeFileName = "fakefile.txt";

        FolderMetadata::EncryptedFile encryptedFile;
        encryptedFile.encryptionKey = EncryptionHelper::generateRandom(16);
        encryptedFile.encryptedFilename = EncryptionHelper::generateRandomFilename();
        encryptedFile.originalFilename = fakeFileName;
        encryptedFile.mimetype = "application/octet-stream";
        encryptedFile.initializationVector = EncryptionHelper::generateRandom(16);
        QVERIFY(metadata->addEncryptedFile(encryptedFile));

        QVERIFY(metadata->addUser(_secondAccount->davUser(), _secondAccount->e2e()->getCertificate(), FolderMetadata::CertificateType::SoftwareNextcloudCertificate));

        QVERIFY(metadata->removeUser(_secondAccount->davUser()));

        QVERIFY(metadata->addUser(_secondAccount->davUser(), _secondAccount->e2e()->getCertificate(), FolderMetadata::CertificateType::SoftwareNextcloudCertificate));

        const auto encryptedMetadata = metadata->encryptedMetadata();
        QVERIFY(!encryptedMetadata.isEmpty());

        const auto signature = metadata->metadataSignature();
        QVERIFY(!signature.isEmpty());

        const auto metaDataDoc = QJsonDocument::fromJson(encryptedMetadata);
        const auto folderUsers = metaDataDoc["users"].toArray();
        QVERIFY(!folderUsers.isEmpty());

        // make sure metadata setup was a success and we can parse and decrypt it with a second account "sharee"
        auto isShareeUserPresentAndCanDecrypt = false;
        for (auto it = folderUsers.constBegin(); it != folderUsers.constEnd(); ++it) {
            const auto folderUserObject = it->toObject();
            const auto userId = folderUserObject.value("userId").toString();

            if (userId != _secondAccount->davUser()) {
                continue;
            }

            const auto certificatePem = folderUserObject.value("certificate").toString().toUtf8();
            const auto certificate = QSslCertificate{certificatePem};
            const auto encryptedMetadataKey = QByteArray::fromBase64(folderUserObject.value("encryptedMetadataKey").toString().toUtf8());

            if (!encryptedMetadataKey.isEmpty()) {
                const auto decryptedMetadataKey = metadata->decryptDataWithPrivateKey(encryptedMetadataKey, _account->e2e()->certificateSha256Fingerprint());
                if (decryptedMetadataKey.isEmpty()) {
                    break;
                }

                const auto metadataObj = metaDataDoc.object()["metadata"].toObject();

                const auto cipherTextEncrypted = metadataObj["ciphertext"].toString().toLocal8Bit();

                // for compatibility, the format is "cipheredpart|initializationVector", so we need to extract the "cipheredpart"
                const auto cipherTextPartExtracted = cipherTextEncrypted.split('|').at(0);

                const auto nonce = QByteArray::fromBase64(metadataObj["nonce"].toString().toLocal8Bit());

                const auto cipherTextDecrypted =
                    EncryptionHelper::decryptThenUnGzipData(decryptedMetadataKey, QByteArray::fromBase64(cipherTextPartExtracted), nonce);
                if (cipherTextDecrypted.isEmpty()) {
                    break;
                }

                const auto cipherTextDocument = QJsonDocument::fromJson(cipherTextDecrypted);
                const auto files = cipherTextDocument.object()["files"].toObject();

                if (files.isEmpty()) {
                    break;
                }

                const auto parsedEncryptedFile = metadata->parseEncryptedFileFromJson(files.keys().first(), files.value(files.keys().first()));

                QCOMPARE(parsedEncryptedFile.originalFilename, fakeFileName);

                isShareeUserPresentAndCanDecrypt = true;
                break;
            }
        }
        QEXPECT_FAIL("", "to be fixed later or removed entirely", Abort);
        QVERIFY(isShareeUserPresentAndCanDecrypt);

        // now, setup existing metadata for the second user "sharee", add a file, and get encrypted JSON again
        auto encryptedMetadataCopy = encryptedMetadata;
        encryptedMetadataCopy.replace("\"", "\\\"");

        QJsonDocument ocsDoc =
            QJsonDocument::fromJson(QStringLiteral("{\"ocs\": {\"data\": {\"meta-data\": \"%1\"}}}").arg(QString::fromUtf8(encryptedMetadataCopy)).toUtf8());

        QScopedPointer<FolderMetadata> metadataFromJsonForSecondUser(new FolderMetadata(_secondAccount, "/", ocsDoc.toJson(), RootEncryptedFolderInfo::makeDefault(), signature, FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupExistingCompleteSpy(metadataFromJsonForSecondUser.data(), &FolderMetadata::setupComplete);
        metadataSetupExistingCompleteSpy.wait();
        QCOMPARE(metadataSetupExistingCompleteSpy.count(), 1);
        QEXPECT_FAIL("", "to be fixed later or removed entirely", Continue);
        QVERIFY(metadataFromJsonForSecondUser->isValid());

        const auto fakeFileNameFromSecondUser = "fakefileFromSecondUser.txt";
        encryptedFile.encryptionKey = EncryptionHelper::generateRandom(16);
        encryptedFile.encryptedFilename = EncryptionHelper::generateRandomFilename();
        encryptedFile.originalFilename = fakeFileNameFromSecondUser;
        encryptedFile.mimetype = "application/octet-stream";
        encryptedFile.initializationVector = EncryptionHelper::generateRandom(16);
        QVERIFY(metadataFromJsonForSecondUser->addEncryptedFile(encryptedFile));

        auto encryptedMetadataFromSecondUser = metadataFromJsonForSecondUser->encryptedMetadata();
        encryptedMetadataFromSecondUser.replace("\"", "\\\"");

        const auto signatureAfterSecondUserModification = metadataFromJsonForSecondUser->metadataSignature();
        QVERIFY(!signatureAfterSecondUserModification.isEmpty());

        QJsonDocument ocsDocFromSecondUser = QJsonDocument::fromJson(
            QStringLiteral("{\"ocs\": {\"data\": {\"meta-data\": \"%1\"}}}").arg(QString::fromUtf8(encryptedMetadataFromSecondUser)).toUtf8());

        QScopedPointer<FolderMetadata> metadataFromJsonForFirstUserToCheckCrossSharing(new FolderMetadata(_account,
                                                                                                          "/",
                                                                                                          ocsDocFromSecondUser.toJson(),
                                                                                                          RootEncryptedFolderInfo::makeDefault(),
                                                                                                          signatureAfterSecondUserModification,
                                                                                                          FolderMetadata::FolderType::Root));
        QSignalSpy metadataSetupForCrossSharingCompleteSpy(metadataFromJsonForFirstUserToCheckCrossSharing.data(), &FolderMetadata::setupComplete);
        metadataSetupForCrossSharingCompleteSpy.wait();
        QCOMPARE(metadataSetupForCrossSharingCompleteSpy.count(), 1);
        QVERIFY(metadataFromJsonForFirstUserToCheckCrossSharing->isValid());

        // now, check if the first user can decrypt metadata and get the file info added by the second user "sharee"
        const auto encryptedMetadataForFirstUserCrossSharing = metadataFromJsonForFirstUserToCheckCrossSharing->encryptedMetadata();
        QVERIFY(!encryptedMetadataForFirstUserCrossSharing.isEmpty());

        const auto metaDataDocForFirstUserCrossSharing = QJsonDocument::fromJson(encryptedMetadataForFirstUserCrossSharing);
        const auto folderUsersForFirstUserCrossSharing = metaDataDocForFirstUserCrossSharing["users"].toArray();
        QVERIFY(!folderUsers.isEmpty());

        // make sure metadata setup was a success and we can parse and decrypt it with a second account "sharee"
        auto isFirstUserPresentAndCanDecrypt = false;
        for (auto it = folderUsersForFirstUserCrossSharing.constBegin(); it != folderUsersForFirstUserCrossSharing.constEnd(); ++it) {
            const auto folderUserObject = it->toObject();
            const auto userId = folderUserObject.value("userId").toString();

            if (userId != _secondAccount->davUser()) {
                continue;
            }

            const auto certificatePem = folderUserObject.value("certificate").toString().toUtf8();
            const auto certificate = QSslCertificate{certificatePem};
            const auto encryptedMetadataKey = QByteArray::fromBase64(folderUserObject.value("encryptedMetadataKey").toString().toUtf8());

            if (!encryptedMetadataKey.isEmpty()) {
                const auto decryptedMetadataKey = metadata->decryptDataWithPrivateKey(encryptedMetadataKey, _account->e2e()->certificateSha256Fingerprint());
                if (decryptedMetadataKey.isEmpty()) {
                    break;
                }

                const auto metadataObj = metaDataDocForFirstUserCrossSharing.object()["metadata"].toObject();

                const auto cipherTextEncrypted = metadataObj["ciphertext"].toString().toLocal8Bit();

                // for compatibility, the format is "cipheredpart|initializationVector", so we need to extract the "cipheredpart"
                const auto cipherTextPartExtracted = cipherTextEncrypted.split('|').at(0);

                const auto nonce = QByteArray::fromBase64(metadataObj["nonce"].toString().toLocal8Bit());

                const auto cipherTextDecrypted =
                    EncryptionHelper::decryptThenUnGzipData(decryptedMetadataKey, QByteArray::fromBase64(cipherTextPartExtracted), nonce);
                if (cipherTextDecrypted.isEmpty()) {
                    break;
                }

                const auto cipherTextDocument = QJsonDocument::fromJson(cipherTextDecrypted);
                const auto files = cipherTextDocument.object()["files"].toObject();

                if (files.isEmpty()) {
                    break;
                }

                FolderMetadata::EncryptedFile foundFile;
                for (auto it = files.constBegin(), end = files.constEnd(); it != end; ++it) {
                    const auto parsedEncryptedFile = metadata->parseEncryptedFileFromJson(it.key(), it.value());
                    if (!parsedEncryptedFile.originalFilename.isEmpty() && parsedEncryptedFile.originalFilename == fakeFileNameFromSecondUser) {
                        foundFile = parsedEncryptedFile;
                    }
                }
                QCOMPARE(foundFile.originalFilename, fakeFileNameFromSecondUser);

                isFirstUserPresentAndCanDecrypt = true;
                break;
            }
        }
        QVERIFY(isFirstUserPresentAndCanDecrypt);
    }
};

QTEST_GUILESS_MAIN(TestClientSideEncryptionV2)
#include "testclientsideencryptionv2.moc"
