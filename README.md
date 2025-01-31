<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Dmugs1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list-totally-not-drugs.txt" at 2025-01-28T18:59:20.9833158Z on the desktop. All of these events began at: 2025-01-28T08:29:50.6542392Z
.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessAccountName == "employee"
| order by Timestamp desc 
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b3f87f8b-af53-4018-a38c-76d456cde70f">






---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows". Based On the logs returned on 2025-01-28T08:33:35.3760523Z, an employee started a process on the device named "dmug-threat-hun." The process involved the execution of the file "tor-browser-windows-x86_64-portable-14.0.4.exe" located in the folder "C:\Users\Employee\Downloads." The SHA256 hash of the file is "095da0bb0c9db5cc23513a511e6f617fc5e278fe31bf48c164c31796f8c3890c." The process was executed with the command line "tor-browser-windows-x86_64-portable-14.0.4.exe /S," indicating a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/38f0eca7-ef74-4cb9-9cbc-7880ffec9890">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for indications that user "employee" actually opened the tor browser. There was evidence that they did open it at 2025-01-28T08:34:01.4121815Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where FileName has_any ("tor.exe", "tor-browser-windows", "firefox.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/42e05e48-6d7f-4af3-adef-1ead201531eb">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection, using any of the known tor ports. On 2025-01-28T08:38:29.400644Z, a successful connection was made from the device named "dmug-threat-hun" by the user account "employee." The process involved the execution of the file "tor.exe." The connection was established to the remote IP address 45.85.117.38 on port 9001.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe", "tor-browser-windows")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/85c355aa-5ae2-4a55-8cdf-14a6042273d6">

---

## Chronological Event Timeline 



### Tor Browser Installation
**Timestamp:** January 28, 2025, 03:33:35 AM  
**Event:** Silent installation of Tor Browser from tor-browser-windows-x86_64-portable-14.0.4.exe.  
**Details:**  
- **File Path:** C:\Users\Employee\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe  
- **Command Line:** tor-browser-windows-x86_64-portable-14.0.4.exe /S  
- **Device:** dmug-threat-hun  
- **Account:** employee  

### Tor Browser Process Creation
**Timestamp:** January 28, 2025, 3:34:01 AM  
**Event:** Execution of tor.exe.  
**Details:**  
- **File Path:** C:\Users\Employee\Desktop\Tor Browser\Browser\Tor Browser\tor.exe  
- **Device:** dmug-threat-hun  
- **Account:** employee  

### Network Connections via Tor
**Timestamp:** January 28, 2025, 3:34:01 AM  
**Event:** Successful network connection by tor.exe.  
**Details:**  
- **Remote IP:** 45.85.117.38  
- **Remote Port:** 9001  
- **Device:** dmug-threat-hun  
- **Account:** employee  

### Tor Browser Usage
**Timestamp:** January 28, 2025, 09:04:42 AM  
**Event:** Evidence of browser usage with multiple processes (firefox.exe and tor.exe) spawned.  
**Details:**  
- **Device:** dmug-threat-hun  
- **Account:** employee  

### File Creation
**Timestamp:** January 28, 2025, 01:59:20 PM  
**Event:** Creation of a suspicious file.  
**Details:**  
- **File Name:** tor-shopping-list-totally-not-drugs.txt  
- **File Path:** C:\Users\Employee\Desktop  
- **Device:** dmug-threat-hun  
- **Account:** employee 

---


## Investigation Summary

The investigation revealed that the employee account on the device "dmug-threat-hun"
- Downloaded and installed Tor Browser silently at 03:29 AM on January 28, 2025.
- Used the browser to establish connections to Tor nodes, indicating activity on the dark web.
- Created suspicious files on the desktop, including "tor-shopping-list-totally-not-drugs.txt" on January 28, 2025, at 1:59:20 PM.

These actions suggest potential misuse of the system warranting further response.


---

## Response Taken

TOR usage was confirmed on the endpoint `dmug-threat-hun` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
