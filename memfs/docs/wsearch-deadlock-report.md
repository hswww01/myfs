# Windows 搜索（mssrch.dll）采集器锁与 USN 监视器锁加锁顺序相反导致死锁

本文是给微软「反馈中心」（Feedback Hub）的报告底稿。把下面"标题"和"详细说明"粘进反馈即可；若支持附件，可附看门狗保存的 SearchIndexer 完整转储。

关于类别：反馈中心的类别树随版本变化，没有"搜索与索引"这一项。在"选择类别"页用关键词 `search` 或 `index` 搜一下，挑最接近的子类即可；常见落点是「文件、文件夹和在线存储」(Files, Folders, and Online Storage)，部分版本在「Windows 桌面环境」下。选不准时就近选一个不影响工程团队定位——正文里的模块名和调用栈才是关键。

## 环境

- Windows 11 Pro，版本 26H2，内部版本 26300.9550
- mssrch.dll / tquery.dll：7.0.26100.8875
- SearchIndexer.exe：7.0.26100.9549

## 标题

SearchIndexer deadlock: CRobotThread and CUsnMonitorNotifier acquire the gatherer lock and the USN monitor lock in opposite order

## 详细说明（可直接粘贴，英文便于工程团队处理）

SearchIndexer (mssrch.dll 7.0.26100.8875) intermittently deadlocks between two threads that take the gatherer lock and the USN-monitor lock in opposite order. Once hung, the service stops answering SERVICE_CONTROL_INTERROGATE; every WMI Win32_Service query then blocks, because cimwin32!CWin32Service::LoadPropertyValuesWin2K calls ControlService(INTERROGATE) on each running service and waits on WSearch.

Thread A — Robot thread (holds gatherer lock, waits for USN-monitor write lock):

    ntdll!RtlEnterCriticalSection
    mssrch!CUsnMonitorNotifier::AddNotificationVolume
    mssrch!CUsnMonNotificationSource::_AddStartAddress
    mssrch!CUsnMonitorNotifier::AddMonitoredAddressWithVolumeInformation
    mssrch!FileSystemMonitoringManager::AddMonitoredAddress
    mssrch!CGatherer::ProcessNotificationDirectory
    mssrch!CGatherer::ProcessDataChange_Internal
    mssrch!CGatherer::ProcessDataChange
    mssrch!CGatherer::OnDataChange
    mssrch!CPluginCollectionSink::PushProperties
    mssrch!CRobotThread::Thread

Thread B — USN monitor thread (holds USN-monitor lock, waits for gatherer lock):

    ntdll!RtlEnterCriticalSection
    mssrch!CGatherer::ProcessDataChange_BeginMulti
    mssrch!CGatherer::OnDataChangeAdvise
    mssrch!CGatherer::OnDataChange
    mssrch!CUsnMonNotificationSource::ProcessNotification
    mssrch!CUsnMonitorNotifier::lokProcessUsnRecord
    mssrch!CUsnMonitorNotifier::Thread

Thread A, while processing a crawled link, adds a new monitored volume and blocks on the USN-monitor lock. Thread B, while processing a USN record, calls back into the gatherer and blocks on the gatherer lock. Classic AB/BA lock-order inversion. All subsequent gatherer timer callbacks (CGatherer::WakeRobotThreadTimerCallback, CGatheringService::PingPlugins) queue on the gatherer lock; in our capture the process had grown to 767 threads, all waiting.

Repro conditions: heavy filesystem churn in indexed scopes (large builds, package installs) concurrent with an index rebuild. It is a race, so it is intermittent.

Impact: WSearch becomes unresponsive and, through the WMI interrogate path above, stalls every Win32_Service consumer on the machine until SearchIndexer is killed and WSearch restarted.

Suggested fix: establish a consistent acquisition order for the gatherer lock and the USN-monitor lock, or drop the gatherer lock before AddNotificationVolume acquires the USN-monitor write lock.
