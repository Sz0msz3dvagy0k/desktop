/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: CC0-1.0
 *
 * This software is in the public domain, furnished "as is", without technical
 * support, and with no warranty, express or implied, as to its usefulness for
 * any purpose.
 */

#include "owncloudpropagator.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QTextStream>

#include <algorithm>

using namespace OCC;
using namespace Qt::StringLiterals;

class DeletedFolderReconciliationBenchmark
{
public:
    static qint64 run(SyncFileItemVector &items)
    {
        QElapsedTimer timer;
        timer.start();
        OwncloudPropagator::adjustDeletedFoldersWithNewChildren(items);
        return timer.nsecsElapsed();
    }
};

static SyncFileItemPtr item(const QString &file, ItemType type, SyncInstructions instruction, SyncFileItem::Direction direction)
{
    auto syncItem = SyncFileItemPtr::create();
    syncItem->_file = file;
    syncItem->_type = type;
    syncItem->_instruction = instruction;
    syncItem->_direction = direction;
    return syncItem;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    constexpr auto folderCount = 11517;
    constexpr auto filesPerFolder = 4;
    constexpr auto extraFiles = 2;
    constexpr auto expectedItemCount = 57588;

    auto items = SyncFileItemVector{
        item(u"Repo"_s, ItemTypeDirectory, CSYNC_INSTRUCTION_REMOVE, SyncFileItem::Down),
    };
    items.reserve(expectedItemCount);
    for (auto folder = 0; folder < folderCount; ++folder) {
        const auto folderPath = u"Repo/dir%1"_s.arg(folder, 5, 10, u'0');
        items.append(item(folderPath, ItemTypeDirectory, CSYNC_INSTRUCTION_NEW, SyncFileItem::Up));
        for (auto file = 0; file < filesPerFolder; ++file) {
            items.append(item(u"%1/file%2"_s.arg(folderPath).arg(file), ItemTypeFile, CSYNC_INSTRUCTION_NEW, SyncFileItem::Up));
        }
    }
    for (auto file = 0; file < extraFiles; ++file) {
        items.append(item(u"Repo/extra%1"_s.arg(file), ItemTypeFile, CSYNC_INSTRUCTION_NEW, SyncFileItem::Up));
    }
    std::sort(items.begin(), items.end());

    if (items.size() != expectedItemCount) {
        qCritical() << "Unexpected benchmark item count:" << items.size();
        return 1;
    }

    const auto elapsedNanoseconds = DeletedFolderReconciliationBenchmark::run(items);
    auto output = QTextStream{stdout};
    output << "adjustDeletedFoldersWithNewChildren: " << items.size() << " items, " << folderCount << " new directories, " << elapsedNanoseconds / 1000000.0
           << " ms" << Qt::endl;

    const auto root = items.constFirst();
    if (root->_file != u"Repo" || root->_instruction != CSYNC_INSTRUCTION_NEW || root->_direction != SyncFileItem::Up) {
        qCritical() << "The removed benchmark root was not changed to an upload";
        return 1;
    }

    return 0;
}
