**To:** security@[organization].com
**Subject:** Malware Analysis Report: Mitigation of Win32/Fynloski (DarkComet RAT)

**Dear Security Team,**

I analyzed a Windows malware sample in an isolated virtual machine and wrote a program that removes it. This report covers what the malware can do, how it persists, how the program neutralizes it, and the attacker address I found.

The sample is `mal-track.exe` (674,304 bytes, SHA-256 `a164abbb6778e1378af208b4a3d4833c2b226c68452d2151fb14e2e01a578fdd`). On VirusTotal, 68 of 70 vendors flag it, with the family labels Fynloski and DarkComet. I analyzed it statically (FLOSS strings, capa, Ghidra decompilation) and dynamically (Process Monitor captures).

**Summary:**

The sample is a remote-access trojan (RAT). It installs itself, connects to a server, and then waits for commands from a remote operator, who can then control the infected machine and spy on its user. Persistence only keeps it running; what makes it malware is what the operator can do through it.

**Capabilities:**

These come from the capa report, the command names found in the sample's strings, and the decompiled command handler. I did not observe the commands being executed; they are capabilities of the sample.

- **Remote command execution.** In the decompiled handler, a message from the server starting with `RunPrompt` or `#BOT#RunPrompt` has the rest of the text executed on the machine through `ShellExecuteA`. capa also detects "execute shell command and capture output", and the strings include remote-shell commands.
- **Spying on the user.** Keystroke logging (through a hook and by polling), screenshots, microphone recording, reading and changing the clipboard, and reading window titles. The strings also include desktop-capture and webcam commands.
- **Control of the machine.** Upload, download, delete, move and rename files, change file attributes, empty the recycle bin, read and delete registry keys and values, create, start, stop and delete services, start and kill processes, and shut down, restart or log off the computer. The strings also include commands to lock the desktop, hide the taskbar and disable Task Manager.
- **Further payloads.** Commands to download a file from a URL and run it (`#BOT#URLDownload`, `URLUpdate`), and to send files over FTP.
- **Attacks and pivoting.** HTTP, SYN and UDP flood commands, SOCKS5 proxy commands, LAN and port scanning, and network share enumeration.
- **Evasion.** Checks for virtual machine and analysis-tool strings, a debugger timing check, self-deletion, process replacement and RWX memory (code injection), and RC4, XOR and zlib encoding of data.
- **Persistence.** capa detects four methods: the `Run` registry key, the Winlogon `Userinit` key, Windows services, and `at` scheduled tasks.

**Impact:**

On a machine outside a controlled environment, an attacker could run any command, read everything the user types, sees and says near the computer, steal and change files, install further malware, and use the machine to attack others.

**Proof of Mitigation:**

The removal program (`maltrack-remediate.exe`, written in Go) finds the malware by its file size and SHA-256, kills the running process, deletes every copy on disk, and removes the persistence and other changes the malware made to the system.


**Before (malware running):**
```bat
C:\Users\vboxuser
λ tasklist | findstr /i maltrack
maltrack.exe                  4484 Console                    1     12,404 K

C:\Users\vboxuser
λ reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    Microsoft Edge Update    REG_SZ    "C:\Users\vboxuser\AppData\Local\Microsoft\EdgeUpdate\1.3.315.17\MicrosoftEdgeUpdateCore.exe"
    ZoomIt    REG_SZ    C:\Tools\sysinternals\ZoomIt64.exe
    Mal-Track    REG_SZ    C:\Users\vboxuser\Documents\maltrack\maltrack.exe

C:\Users\vboxuser
λ dir /a "%USERPROFILE%\Documents\maltrack"
 Volume in drive C has no label.
 Volume Serial Number is 8A9B-2277

 Directory of C:\Users\vboxuser\Documents\maltrack

11/25/2026  11:31 AM    <DIR>          .
11/25/2026  11:31 AM    <DIR>          ..
06/08/2022  12:02 PM           674,304 maltrack.exe
               1 File(s)        674,304 bytes
               2 Dir(s)  23,591,710,720 bytes free

C:\Users\vboxuser
λ dir /a "%APPDATA%\dclogs"
 Volume in drive C has no label.
 Volume Serial Number is 8A9B-2277

 Directory of C:\Users\vboxuser\AppData\Roaming\dclogs

11/25/2026  11:31 AM    <DIR>          .
11/25/2026  11:31 AM    <DIR>          ..
11/25/2026  11:32 AM               624 2026-11-25-4.dc
               1 File(s)            624 bytes
               2 Dir(s)  23,591,710,720 bytes free

C:\Users\vboxuser
λ reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
```

**After running `maltrack-remediate.exe`:**
```bat
C:\Users\vboxuser
λ tasklist | findstr /i maltrack

C:\Users\vboxuser
λ reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    Microsoft Edge Update    REG_SZ    "C:\Users\vboxuser\AppData\Local\Microsoft\EdgeUpdate\1.3.315.17\MicrosoftEdgeUpdateCore.exe"
    ZoomIt    REG_SZ    C:\Tools\sysinternals\ZoomIt64.exe

C:\Users\vboxuser
λ dir /a "%USERPROFILE%\Documents\maltrack"
 Volume in drive C has no label.
 Volume Serial Number is 8A9B-2277

 Directory of C:\Users\vboxuser\Documents

File Not Found

C:\Users\vboxuser
λ dir /a "%APPDATA%\dclogs"
 Volume in drive C has no label.
 Volume Serial Number is 8A9B-2277

 Directory of C:\Users\vboxuser\AppData\Roaming

File Not Found

C:\Users\vboxuser
λ reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
```

The malware process is gone, the `Mal-Track` value is removed from the Run key (the other entries are untouched), the dropped `maltrack.exe` and its folder are deleted, and the `dclogs` folder is deleted.

**Attacker Information:**

The malware communicated with the following IP address: `127.0.0.1`.

The address is hardcoded in the sample (`127.0.0.1:1604` in its strings and decompiled code), and the capture shows `maltrack.exe` connecting to `127.0.0.1:1010`.

Please feel free to reach out for further clarification or additional details.

**Best regards,**
xySaad
