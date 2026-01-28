<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/acRei/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "skyline_" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-28T13:09:55.9198135Z`. These events began at `2026-01-28T12:58:54.966004Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "sky-vm"  
| where InitiatingProcessAccountName == "skyline_"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="2478" height="708" alt="image" src="https://github.com/user-attachments/assets/6aa009e4-90db-46a3-abe1-66850106ce67" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-01-28T13:00:32.1905297Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "sky-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="2233" height="241" alt="image" src="https://github.com/user-attachments/assets/08dfcfb6-e541-4a40-af4a-a0a30f3c8e2b" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "skyline_" actually opened the TOR browser. There was evidence that they did open it at `2026-01-28T13:00:54.7141922Z`. There were several other instances, such as `firefox.exe` (TOR) and `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sky-vm"
| where FileName has_any ("tor-browser-windows-x86_64-portable-.exe", "torbrowser-install-.exe", "tor-browser-windows-i686-portable-*.exe", "Start Tor Browser.exe", "firefox.exe", "tor.exe", "Browser\firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="2442" height="1051" alt="image" src="https://github.com/user-attachments/assets/32bfe0e6-f463-4a6d-bdc5-b2ca8e47bf0c" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-28T13:06:32.8460069Z`, an employee on the "sky-vm" device successfully established a connection to the remote IP address `145.220.0.15` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\skyline_\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sky-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9050", "9051", "9150", "9151", "8118", "9001", "9030", "9040", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="2471" height="751" alt="image" src="https://github.com/user-attachments/assets/6b1916b3-dc26-4d25-8fe4-942022404658" />

---

## Chronological Events

### 1. Initial Tor-Related File Activity Begins

**Timestamp:** 2026-01-28T12:58:54.966004Z

* **Log Source:** DeviceFileEvents
* **Observation:**
   * First appearance of files containing the string "tor" on sky-vm
   * Initiated by user skyline_
* **Significance:**
   * Marks the start of Tor-related activity on the host
   * Indicates the Tor installer was likely downloaded shortly before execution

---

### 2. Tor Browser Installer Executed

**Timestamp:** 2026-01-28T13:00:32.1905297Z

* **Log Source:** DeviceProcessEvents
* **Artifact:**
   * `tor-browser-windows-x86_64-portable-15.0.4.exe`
* **ActionType:** ProcessCreated
* **Significance:**
   * Confirms the Tor Browser installer was manually executed
   * Portable installer suggests no admin privileges were required
   * Strong evidence of intentional Tor installation

---

### 3. Tor Browser Launched

**Timestamp:** 2026-01-28T13:00:54.7141922Z

* **Log Source:** DeviceProcessEvents
* **Artifacts Observed:**
   * `Start Tor Browser.exe`
   * `firefox.exe` (Tor Browser variant)
   * `tor.exe`
* **Significance:**
   * Confirms the Tor Browser was successfully opened
   * Firefox spawning alongside `tor.exe` is consistent with Tor Browser architecture
   * Indicates transition from installation → active use

---

### 4. Tor Browser Files Copied to Desktop

**Timestamp Range:**
* Start: 2026-01-28T12:58:54Z
* Key File Creation: 2026-01-28T13:09:55.9198135Z

* **Log Source:** DeviceFileEvents
* **Artifacts:**
   * Multiple Tor-related files copied to the Desktop
   * Creation of `tor-shopping-list.txt`
* **Significance:**
   * Confirms Tor Browser was extracted or installed to the Desktop
   * The creation of `tor-shopping-list.txt` suggests user activity during or after Tor usage
   * Indicates user interaction, not just passive installation

---

### 5. Tor Network Connection Established

**Timestamp:** 2026-01-28 08:04:35 AM (local time)

* **Log Source:** DeviceNetworkEvents
* **Process:** `tor.exe`
* **Remote IP:** 145.220.0.15
* **Remote Port:** 9001
* **Remote URL:** https://www.ooulfr3ewd.com
* **Significance:**
   * Definitive proof of Tor network usage
   * Port 9001 is a standard Tor relay port
   * Confirms Tor Browser successfully routed traffic through the Tor network
   * Establishes anonymized outbound communication

---

### 6. Additional Encrypted Tor Traffic

**Timestamp:** Shortly after initial Tor relay connection

* **Log Source:** DeviceNetworkEvents
* **Ports Observed:** 443
* **Process:** `tor.exe` / `firefox.exe`
* **Significance:**
   * Indicates normal Tor Browser web activity
   * Tor often tunnels traffic over HTTPS (443) to blend in
   * Supports conclusion that Tor Browser remained actively in use

---

## Summary

On January 28, 2026, user **skyline_** intentionally downloaded, installed, and used the Tor Browser on host **sky-vm**. The activity began with Tor-related file creation, followed by execution of the Tor Browser portable installer. Shortly after installation, the user launched Tor Browser, resulting in the creation of multiple Tor-related files on the Desktop and a user-created file named `tor-shopping-list.txt`, indicating active user interaction during the session.

Network telemetry confirms that Tor Browser successfully established connections to the Tor network, including a direct connection to a known Tor relay over port 9001, followed by additional encrypted connections over port 443. These findings collectively demonstrate successful Tor Browser usage, not merely installation.

No evidence suggests accidental execution, background installation, or automated activity — all actions align with deliberate user-driven Tor usage.

---

## Response Taken

TOR usage was confirmed on the endpoint `sky-vm` by the user `skyline_`. The device was isolated, and the user's direct manager was notified.

---
