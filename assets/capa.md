## MITRE ATT&CK

| Tactic                   | Technique                                                                         |
| ------------------------ | --------------------------------------------------------------------------------- |
| **Collection**           | Audio Capture `T1123`                                                             |
|                          | Clipboard Data `T1115`                                                            |
|                          | Input Capture::Keylogging `T1056.001`                                             |
|                          | Screen Capture `T1113`                                                            |
| **Defense Evasion**      | File and Directory Permissions Modification `T1222`                               |
|                          | Hide Artifacts `T1564`                                                            |
|                          | Hide Artifacts::Hidden Window `T1564.003`                                         |
|                          | Indicator Removal::File Deletion `T1070.004`                                      |
|                          | Modify Registry `T1112`                                                           |
|                          | Obfuscated Files or Information `T1027`                                           |
|                          | Process Injection::Process Hollowing `T1055.012`                                  |
|                          | Reflective Code Loading `T1620`                                                   |
|                          | Virtualization/Sandbox Evasion::System Checks `T1497.001`                         |
| **Discovery**            | Account Discovery `T1087`                                                         |
|                          | Application Window Discovery `T1010`                                              |
|                          | File and Directory Discovery `T1083`                                              |
|                          | Network Share Discovery `T1135`                                                   |
|                          | Query Registry `T1012`                                                            |
|                          | System Information Discovery `T1082`                                              |
|                          | System Location Discovery `T1614`                                                 |
|                          | System Location Discovery::System Language Discovery `T1614.001`                  |
|                          | System Network Configuration Discovery `T1016`                                    |
|                          | System Owner/User Discovery `T1033`                                               |
|                          | System Service Discovery `T1007`                                                  |
| **Execution**            | Command and Scripting Interpreter `T1059`                                         |
|                          | Command and Scripting Interpreter::Windows Command Shell `T1059.003`              |
|                          | Shared Modules `T1129`                                                            |
|                          | System Services::Service Execution `T1569.002`                                    |
| **Impact**               | Endpoint Denial of Service `T1499`                                                |
|                          | Service Stop `T1489`                                                              |
|                          | System Shutdown/Reboot `T1529`                                                    |
| **Persistence**          | Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder `T1547.001` |
|                          | Boot or Logon Autostart Execution::Winlogon Helper DLL `T1547.004`                |
|                          | Create or Modify System Process::Windows Service `T1543.003`                      |
|                          | Scheduled Task/Job::At `T1053.002`                                                |
| **Privilege Escalation** | Access Token Manipulation `T1134`                                                 |

---

## Malware Behavior Catalog (MBC)

| Objective                    | Behavior                                                                 |
| ---------------------------- | ------------------------------------------------------------------------ |
| **Anti-Behavioral Analysis** | Debugger Detection::Timing/Delay Check GetTickCount `B0001.032`          |
|                              | Virtual Machine Detection `B0009`                                        |
| **Collection**               | Keylogging::Application Hook `F0002.001`                                 |
|                              | Keylogging::Polling `F0002.002`                                          |
|                              | Screen Capture::WinAPI `E1113.m01`                                       |
| **Command and Control**      | C2 Communication::Receive Data `B0030.002`                               |
|                              | C2 Communication::Send Data `B0030.001`                                  |
| **Communication**            | DNS Communication::Resolve `C0011.001`                                   |
|                              | FTP Communication::Send File `C0004.001`                                 |
|                              | FTP Communication::WinINet `C0004.002`                                   |
|                              | HTTP Communication::Connect to Server `C0002.009`                        |
|                              | HTTP Communication::Create Request `C0002.012`                           |
|                              | HTTP Communication::Download URL `C0002.006`                             |
|                              | HTTP Communication::Get Response `C0002.017`                             |
|                              | HTTP Communication::Open URL `C0002.004`                                 |
|                              | Interprocess Communication::Create Pipe `C0003.001`                      |
|                              | Interprocess Communication::Read Pipe `C0003.003`                        |
|                              | Socket Communication::Connect Socket `C0001.004`                         |
|                              | Socket Communication::Create Socket `C0001.003`                          |
|                              | Socket Communication::Create TCP Socket `C0001.011`                      |
|                              | Socket Communication::Get Socket Status `C0001.012`                      |
|                              | Socket Communication::Initialize Winsock Library `C0001.009`             |
|                              | Socket Communication::Receive Data `C0001.006`                           |
|                              | Socket Communication::Send Data `C0001.007`                              |
|                              | Socket Communication::Set Socket Config `C0001.001`                      |
|                              | Socket Communication::Start TCP Server `C0001.005`                       |
|                              | Socket Communication::TCP Client `C0001.008`                             |
| **Cryptography**             | Encrypt Data::RC4 `C0027.009`                                            |
|                              | Encryption Key::RC4 KSA `C0028.002`                                      |
|                              | Generate Pseudo-random Sequence `C0021`                                  |
|                              | Generate Pseudo-random Sequence::RC4 PRGA `C0021.004`                    |
| **Data**                     | Compress Data `C0024`                                                    |
|                              | Compression Library `C0060`                                              |
|                              | Encode Data::XOR `C0026.002`                                             |
| **Defense Evasion**          | Obfuscated Files or Information::Encoding-Standard Algorithm `E1027.m02` |
|                              | Self Deletion::COMSPEC Environment Variable `F0007.001`                  |
| **Discovery**                | Analysis Tool Discovery::Process detection `B0013.001`                   |
|                              | Application Window Discovery `E1010`                                     |
|                              | Code Discovery::Inspect Section Memory Permissions `B0046.002`           |
|                              | File and Directory Discovery `E1083`                                     |
|                              | System Information Discovery `E1082`                                     |
|                              | Taskbar Discovery `B0043`                                                |
| **Execution**                | Command and Scripting Interpreter `E1059`                                |
| **File System**              | Copy File `C0045`                                                        |
|                              | Create Directory `C0046`                                                 |
|                              | Delete File `C0047`                                                      |
|                              | Get File Attributes `C0049`                                              |
|                              | Move File `C0063`                                                        |
|                              | Read File `C0051`                                                        |
|                              | Set File Attributes `C0050`                                              |
|                              | Writes File `C0052`                                                      |
| **Impact**                   | Clipboard Modification `E1510`                                           |
| **Memory**                   | Allocate Memory `C0007`                                                  |
| **Operating System**         | Environment Variable `C0034`                                             |
|                              | Registry::Delete Registry Key `C0036.002`                                |
|                              | Registry::Delete Registry Value `C0036.007`                              |
|                              | Registry::Query Registry Key `C0036.005`                                 |
|                              | Registry::Query Registry Value `C0036.006`                               |
|                              | Registry::Set Registry Key `C0036.001`                                   |
| **Persistence**              | Registry Run Keys / Startup Folder `F0012`                               |
| **Process**                  | Create Mutex `C0042`                                                     |
|                              | Create Process `C0017`                                                   |
|                              | Create Process::Create Suspended Process `C0017.003`                     |
|                              | Create Thread `C0038`                                                    |
|                              | Resume Thread `C0054`                                                    |
|                              | Set Thread Local Storage Value `C0041`                                   |
|                              | Terminate Process `C0018`                                                |

---

## Capabilities

| Capability                                               | Namespace                                         |
| -------------------------------------------------------- | ------------------------------------------------- |
| inspect load icon resource                               | `anti-analysis`                                   |
| reference analysis tools strings                         | `anti-analysis`                                   |
| check for time delay via GetTickCount                    | `anti-analysis/anti-debugging/debugger-detection` |
| self delete (3 matches)                                  | `anti-analysis/anti-forensic/self-deletion`       |
| reference anti-VM strings                                | `anti-analysis/anti-vm/vm-detection`              |
| get geographical location (5 matches)                    | `collection`                                      |
| log keystrokes (4 matches)                               | `collection/keylog`                               |
| log keystrokes via application hook                      | `collection/keylog`                               |
| log keystrokes via polling (14 matches)                  | `collection/keylog`                               |
| capture microphone audio (3 matches)                     | `collection/microphone`                           |
| capture screenshot (2 matches)                           | `collection/screenshot`                           |
| receive data (21 matches)                                | `communication`                                   |
| send data (27 matches)                                   | `communication`                                   |
| execute shell command and capture output                 | `communication/c2/shell`                          |
| resolve DNS (21 matches)                                 | `communication/dns`                               |
| send file using FTP                                      | `communication/ftp/send`                          |
| connect to HTTP server                                   | `communication/http/client`                       |
| create two anonymous pipes                               | `communication/named-pipe/create`                 |
| create raw socket                                        | `communication/socket`                            |
| get socket information                                   | `communication/socket`                            |
| get socket status                                        | `communication/socket`                            |
| initialize Winsock library (2 matches)                   | `communication/socket`                            |
| set socket configuration                                 | `communication/socket`                            |
| act as TCP client (17 matches)                           | `communication/tcp/client`                        |
| start TCP server                                         | `communication/tcp/serve`                         |
| compiled with Borland Delphi                             | `compiler/delphi`                                 |
| compress data via ZLIB inflate or deflate                | `data-manipulation/compression`                   |
| encode data using XOR (3 matches)                        | `data-manipulation/encoding/xor`                  |
| encrypt data using RC4 KSA (2 matches)                   | `data-manipulation/encryption/rc4`                |
| encrypt data using RC4 PRGA (2 matches)                  | `data-manipulation/encryption/rc4`                |
| generate random numbers using the Delphi LCG             | `data-manipulation/prng/lcg`                      |
| contain a thread local storage (.tls) section            | `executable/pe/section/tls`                       |
| extract resource via kernel32 functions (5 matches)      | `executable/resource`                             |
| accept command line arguments (3 matches)                | `host-interaction/cli`                            |
| open clipboard                                           | `host-interaction/clipboard`                      |
| read clipboard data (6 matches)                          | `host-interaction/clipboard`                      |
| write clipboard data (3 matches)                         | `host-interaction/clipboard`                      |
| get common file path (14 matches)                        | `host-interaction/file-system`                    |
| get file system object information                       | `host-interaction/file-system`                    |
| copy file (3 matches)                                    | `host-interaction/file-system/copy`               |
| create directory (2 matches)                             | `host-interaction/file-system/create`             |
| delete file (7 matches)                                  | `host-interaction/file-system/delete`             |
| check if file exists (2 matches)                         | `host-interaction/file-system/exists`             |
| get file attributes (2 matches)                          | `host-interaction/file-system/meta`               |
| get file version info                                    | `host-interaction/file-system/meta`               |
| set file attributes (13 matches)                         | `host-interaction/file-system/meta`               |
| move file                                                | `host-interaction/file-system/move`               |
| read file on Windows (5 matches)                         | `host-interaction/file-system/read`               |
| read file via mapping                                    | `host-interaction/file-system/read`               |
| clear file content (2 matches)                           | `host-interaction/file-system/write`              |
| write file on Windows (8 matches)                        | `host-interaction/file-system/write`              |
| enumerate gui resources (6 matches)                      | `host-interaction/gui`                            |
| set global application hook                              | `host-interaction/gui`                            |
| lock the desktop (2 matches)                             | `host-interaction/gui/session/lock`               |
| hide the Windows taskbar (3 matches)                     | `host-interaction/gui/taskbar/hide`               |
| get graphical window text (8 matches)                    | `host-interaction/gui/window/get-text`            |
| get number of processors                                 | `host-interaction/hardware/cpu`                   |
| get keyboard layout (4 matches)                          | `host-interaction/hardware/keyboard`              |
| get memory capacity (2 matches)                          | `host-interaction/hardware/memory`                |
| power down monitor                                       | `host-interaction/hardware/monitor`               |
| get disk information (4 matches)                         | `host-interaction/hardware/storage`               |
| get disk size                                            | `host-interaction/hardware/storage`               |
| create or open mutex on Windows                          | `host-interaction/mutex`                          |
| enumerate network shares                                 | `host-interaction/network`                        |
| get local IPv4 addresses                                 | `host-interaction/network/address`                |
| shutdown system                                          | `host-interaction/os`                             |
| get hostname (4 matches)                                 | `host-interaction/os/hostname`                    |
| get system information on Windows                        | `host-interaction/os/info`                        |
| get thread local storage value                           | `host-interaction/process`                        |
| create process on Windows (39 matches)                   | `host-interaction/process/create`                 |
| allocate or change RWX memory (7 matches)                | `host-interaction/process/inject`                 |
| use process replacement                                  | `host-interaction/process/inject`                 |
| modify access privileges (2 matches)                     | `host-interaction/process/modify`                 |
| terminate process (9 matches)                            | `host-interaction/process/terminate`              |
| empty the recycle bin                                    | `host-interaction/recycle-bin`                    |
| query or enumerate registry key (5 matches)              | `host-interaction/registry`                       |
| query or enumerate registry value (7 matches)            | `host-interaction/registry`                       |
| delete registry key (4 matches)                          | `host-interaction/registry/delete`                |
| delete registry value (3 matches)                        | `host-interaction/registry/delete`                |
| query service status                                     | `host-interaction/service`                        |
| create service                                           | `host-interaction/service/create`                 |
| delete service                                           | `host-interaction/service/delete`                 |
| enumerate services                                       | `host-interaction/service/list`                   |
| start service (2 matches)                                | `host-interaction/service/start`                  |
| stop service (2 matches)                                 | `host-interaction/service/stop`                   |
| get session user name                                    | `host-interaction/session`                        |
| get token privileges (2 matches)                         | `host-interaction/session`                        |
| create thread (34 matches)                               | `host-interaction/thread/create`                  |
| set thread local storage value                           | `host-interaction/thread/tls`                     |
| get kernel32 base address (2 matches)                    | `linking/runtime-linking`                         |
| link function at runtime on Windows (165 matches)        | `linking/runtime-linking`                         |
| link many functions at runtime (9 matches)               | `linking/runtime-linking`                         |
| linked against ZLIB                                      | `linking/static/zlib`                             |
| inspect section memory permissions                       | `load-code/pe`                                    |
| parse PE header (2 matches)                              | `load-code/pe`                                    |
| resolve function by parsing PE exports                   | `load-code/pe`                                    |
| persist via Run registry key (5 matches)                 | `persistence/registry/run`                        |
| persist via Winlogon Helper DLL registry key (2 matches) | `persistence/registry/winlogon-helper`            |
| schedule task via at (3 matches)                         | `persistence/scheduled-tasks`                     |
| persist via Windows service                              | `persistence/service`                             |
| identify system language via API                         | `targeting/language`                              |
