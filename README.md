<img width="768" height="512" alt="ChatGPT Image Jun 6, 2026, 02_15_50 PM" src="https://github.com/user-attachments/assets/2f03d2c3-a38b-49dc-827c-00f4849d379d" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/lea-escober/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table
A review of the DeviceFileEvents table was conducted to identify any files containing the string "tor". The results revealed that the user account "lea" on device "lea-threat-hunt" downloaded a Tor Browser installer and subsequently generated numerous Tor-related files on the system. File activity indicates that Tor Browser components were extracted or copied to the user's Desktop, resulting in the creation of the Tor Browser directory structure. Additionally, a file named `tor-shopping-list.txt` was created on the Desktop. The earliest observed Tor-related file activity occurred at `2026-06-04T21:52:18.9467969Z`, providing the first indication of Tor Browser introduction onto the system.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "lea-threat-hunt"
| where InitiatingProcessAccountName == "lea"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1807" height="512" alt="image" src="https://github.com/user-attachments/assets/b7c9bbd7-58c5-46e3-9ae9-3f8ab34f0a3a" />

---

### 2. Searched the `DeviceProcessEvents` Table

A review of the DeviceProcessEvents table was conducted to identify process executions associated with the Tor Browser installer `tor-browser-windows-x86_64-portable-15.0.15.exe`. The investigation revealed that at `2026-06-04T21:54:50.5553783Z`, the user account "lea" on device "lea-threat-hunt" executed the installer directly from the Downloads directory (`C:\Users\Lea\Downloads`). The process was launched with the `/S` command-line parameter, indicating that the application was installed or extracted in silent mode, suppressing installation prompts and requiring no user interaction. This activity confirms the intentional execution of a portable Tor Browser package and the subsequent deployment of Tor Browser components onto the system. The use of silent installation parameters may reduce visible indicators of installation activity while enabling anonymous internet access through the Tor network.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "lea-threat-hunt"
| where FileName contains "tor"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc  
```
<img width="1690" height="372" alt="image" src="https://github.com/user-attachments/assets/e035cc8e-aa26-42d6-90df-69c3b04c9555" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Analysis of `DeviceProcessEvents` showed that the user account "lea" launched Tor Browser on the device "lea-threat-hunt." The activity included execution of `tor.exe`, which establishes connections to the Tor network, followed by the creation of multiple `firefox.exe` child processes associated with the Tor Browser application. While the process activity confirms that Tor Browser was opened and initialized successfully, additional network telemetry would be required to determine whether the browser was actively used to access websites or transfer data through the Tor network. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "lea-threat-hunt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1647" height="506" alt="image" src="https://github.com/user-attachments/assets/4ba42407-c08a-462b-8496-9ab5ad1a3a8f" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Analysis of `DeviceNetworkEvents` showed that the user account "lea" on the device "lea-threat-hunt" successfully established multiple outbound network connections associated with Tor Browser activity. The process `tor.exe` connected to several external public IP addresses over TCP port `9001`, a port commonly used by Tor relay nodes to route encrypted traffic through the Tor network. Connections were observed to multiple remote systems, including IP addresses `65.109.233.53`, `89.190.5.230`, and `57.129.62.226`, indicating that Tor successfully joined and communicated with the Tor network. In addition, `firefox.exe` established a connection to the local address `127.0.0.1` on port `9150`, which is the default SOCKS proxy port used by Tor Browser to route web traffic through the Tor service. These successful network connections confirm that Tor Browser was not only launched but also successfully initialized and actively communicating with the Tor network at the time of the observed activity. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "lea-threat-hunt"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1407" height="342" alt="image" src="https://github.com/user-attachments/assets/b9e33419-1a17-4d34-ba2d-16600f4c4fe2" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
