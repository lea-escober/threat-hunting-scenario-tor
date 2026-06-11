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

### 1. Tor-Related File Activity Detected

- **Timestamp:** `2026-06-04T21:52:18.9467969Z`
- **Event:** The user account "lea" on device "lea-threat-hunt" generated Tor-related file activity. Multiple files associated with Tor Browser were created, extracted, or copied to the Desktop, including the creation of a file named "tor-shopping-list.txt".
- **Action:** Tor Browser files were introduced onto the system and extracted to the user's Desktop.
- **File Path:** `C:\Users\Lea\Desktop\Tor Browser\`
- **Evidence:**  DeviceFileEvents logs containing filenames with the string "tor".

### 2. Tor Browser Installer Executed

- **Timestamp:** `2026-06-04T21:54:50.5553783Z`
- **Event:** The user account "lea" executed the Tor Browser installer `tor-browser-windows-x86_64-portable-15.0.15.exe` from the Downloads directory.
- **Action:** Silent installation/extraction initiated using the **/S** command-line parameter.
- **Process:** `tor-browser-windows-x86_64-portable-15.0.15.exe /S`
- **File Path:** `C:\Users\Lea\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

### 3. Tor Service Started

- **Timestamp:** `2026-06-04T21:55:37Z`
- **Event:** The Tor Browser application launched the **tor.exe** process.
- **Action:** Tor service initialization detected.
- **Process:** `tor.exe`
- **Purpose:** Establishes connectivity to the Tor network and creates Tor circuits.
- **File Path:** `C:\Users\Lea\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Tor Browser Opened

- **Timestamp:** `2026-06-04T21:55:24Z – 2026-06-04T21:55:34Z`
- **Event:** Multiple `firefox.exe` processes associated with Tor Browser were created.
- **Action:** Tor Browser successfully launched
- **Processes:** `firefox.exe`
- **Evidence:** Parent-child process relationships originating from Tor Browser installation directories.
- **File Path:** `C:\Users\Lea\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Initial Connection to Tor Network

- **Timestamp:** `2026-06-04T21:55:45Z`
- **Event:** The Tor service established an outbound connection to a Tor relay node.
- **Action:** Successful network communication with the Tor network.
- **Process:** `tor.exe`
- **Remote IP:** `65.109.233.53`
- **Remote Port:** `9001`

### 6. Browser Traffic Routed Through Tor Proxy

- **Timestamp:** `2026-06-04T21:56:03Z`
- **Event:** Tor Browser connected to the local SOCKS proxy service.
- **Action:** Browser traffic began routing through Tor.
- **Process:** `firefox.exe`
- **Remote IP:** `127.0.0.1`
- **Remote Port:** `9150`

### 7. Additional Tor Relay Communications

- **Timestamp:** `2026-06-04T21:56:40Z – 2026-06-04T21:56:57Z`
- **Event:** Tor established additional relay connections to maintain Tor circuits.
- **Action:**  Continued participation in the Tor network.
- **Process:** `tor.exe`
- **Remote IPs:** `89.190.5.230:9001` and `57.129.62.226:9001`

### 8. Continued Tor Browser Activity

- **Timestamp:** `2026-06-04T22:19:30Z – 2026-06-04T22:19:41Z`
- **Event:** Additional Tor-related process and network activity was observed.
- **Action:**  Tor Browser continued communicating with Tor relay infrastructure.
- **Process:** `tor.exe`
- **Remote IPs:** `65.109.233.53:9001` and `89.190.5.230:9001`

---

## Investigation Findings

The collected evidence establishes the following sequence of events:

1. Tor Browser-related files were introduced onto the system under the user account **lea**.
2. The portable Tor Browser installer was executed from the Downloads folder using silent installation parameters.
3. Tor Browser files were extracted to the Desktop.
4. The Tor service (**tor.exe**) was launched and initialized successfully.
5. Multiple Tor Browser Firefox processes were created.
6. The Tor client established outbound connections to known Tor relay infrastructure over TCP port **9001**.
7. Firefox successfully connected to the local Tor SOCKS proxy on port **9150**.
8. Additional relay communications occurred after startup, demonstrating continued participation in the Tor network.

---

## Summary

The investigation confirmed that the user account **lea** intentionally executed a portable version of Tor Browser on the device **lea-threat-hunt**. Following execution, Tor Browser was extracted to the Desktop, the Tor service was launched, multiple Firefox-based Tor Browser processes were created, and successful network communications were established with several external Tor relay nodes. Network telemetry further showed Firefox routing traffic through the local Tor SOCKS proxy, confirming that Tor Browser successfully initialized and was operational.

The evidence supports the conclusion that Tor Browser was not merely downloaded but was actively executed and connected to the Tor network. While the telemetry confirms Tor network usage, the available logs do not definitively identify which websites were visited or what content was accessed through the browser.

---

## Response Taken

TOR usage was confirmed on the endpoint `lea-threat-hunt` by the user `lea`. The device was isolated, and the user's direct manager was notified.

---
