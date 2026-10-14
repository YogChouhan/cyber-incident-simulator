# Cyber Incident Response Simulator

A modular, beginner-friendly standard **C++17** console simulation environment designed for cybersecurity operations and incident handling, built to demonstrate core Object-Oriented Programming (OOP) concepts for university academic submissions.

---

## 1. Project Directory Structure

```
cyber-incident-simulator/
├── CMakeLists.txt
├── README.md
├── .gitignore
├── include/
│   ├── Device.h         # Abstract NetworkDevice base class and derived Server, Workstation, Firewall
│   ├── Incident.h       # Abstract SecurityIncident base class and derived MalwareIncident, DDoSIncident
│   └── Simulator.h      # SimulatorApp manager declaration
└── src/
    ├── Device.cpp       # Device member functions, diagnostic routines, and polymorphism
    ├── Incident.cpp     # Incident investigation, remediation menus, and dynamic dispatch
    ├── Simulator.cpp    # SimulatorApp runtime loop, incident generator, and file export
    └── main.cpp         # Main entry point with exception handling
```

---

## 2. How the Code Works

- **Inheritance** allows derived classes to reuse common attributes and add specific ones; `Server`, `Workstation`, and `Firewall` inherit from `NetworkDevice` (`include/Device.h`), while `MalwareIncident` and `DDoSIncident` inherit from `SecurityIncident` (`include/Incident.h`).
- **Abstract Classes** define shared interfaces with pure virtual functions (`= 0`) that cannot be instantiated directly, seen in `NetworkDevice` (`include/Device.h`) and `SecurityIncident` (`include/Incident.h`).
- **Virtual Functions & Polymorphism** enable dynamic dispatch at runtime; calling `investigate()` or `applyResponse()` on a `SecurityIncident*` executes the derived class method (`src/Incident.cpp`), which then calls `performDiagnostics()` on the attached device (`src/Device.cpp`).
- **Memory Management via `std::unique_ptr`** guarantees automatic cleanup and single ownership of devices and incidents within `SimulatorApp` (`include/Simulator.h`, `src/Simulator.cpp`), avoiding memory leaks.
- **Non-Owning References** use simple raw pointers (`NetworkDevice* m_targetDevice`) to reference affected devices without transferring ownership (`include/Incident.h`).
- **File Handling** uses standard `std::ofstream` to format and export real-time network states and incident audit logs directly to a `.txt` file (`src/Simulator.cpp`).

---

## 3. Core OOP Principles Demonstrated

| Concept | Implementation Details |
|---|---|
| **Encapsulation** | Private/protected member variables across all classes with controlled accessor (`getters`) and mutator (`setters`) methods (`include/Device.h`, `include/Incident.h`). |
| **Inheritance** | Base class `NetworkDevice` inherited by `Server`, `Workstation`, and `Firewall`. Base class `SecurityIncident` inherited by `MalwareIncident` and `DDoSIncident`. |
| **Abstract Classes** | `NetworkDevice` contains pure virtual functions (`getDeviceRole() = 0`, `displayInfo() = 0`, `performDiagnostics() = 0`). `SecurityIncident` contains pure virtual functions (`investigate() = 0`, `applyResponse() = 0`, `printResponseOptions() = 0`, `getIncidentType() = 0`, `getDetailedReport() = 0`). |
| **Polymorphism & Dynamic Dispatch** | Virtual functions are overridden with `override`. When investigating incidents, runtime dynamic dispatch selects the correct subclass method (`MalwareIncident::investigate()` vs `DDoSIncident::investigate()`) and invokes device diagnostics polymorphically. |
| **Memory Management** | Device and incident lifecycles are managed via `std::vector<std::unique_ptr<NetworkDevice>>` and `std::vector<std::unique_ptr<SecurityIncident>>`. Raw pointers (`NetworkDevice* m_targetDevice`) are used strictly as non-owning references. |
| **File Handling** | Reports are generated using standard `<fstream>` (`std::ofstream`) to export a structured audit log to `cyber_incident_report.txt`. |
| **Platform Target** | Targets Windows (MinGW-w64). |

---

## 4. How to Build and Run (Windows MinGW-w64)

Open a terminal in the `cyber-incident-simulator` project directory:

```powershell
g++ -std=c++17 -Wall -Wextra -pedantic -Iinclude src/main.cpp src/Device.cpp src/Incident.cpp src/Simulator.cpp -o CyberIncidentSimulator.exe
.\CyberIncidentSimulator.exe
```

---

## 5. Application Workflow & Features

1. **View Network Status**: Displays all registered hosts, IP addresses, operational roles, and health statuses (`ONLINE`, `COMPROMISED`, `UNDER_ATTACK`, `ISOLATED`, `OFFLINE`). Supports deep diagnostic inspection for any selected host.
2. **View All Incidents**: Summarizes the complete list of active, investigating, contained, and resolved security incidents with threat severity and target hosts.
3. **Investigate & Respond to Incident**: 
   - Displays attack forensic telemetry and executes device diagnostics polymorphically.
   - Offers context-specific containment actions:
     - *Malware*: Network Isolation, Process Termination, Full System Restoration.
     - *DDoS*: Traffic Scrubbing, Rate Limiting & Filter, Flush & Reset Services.
4. **Generate Random Incident**: Randomly targets an available `ONLINE` device, creates a new incident (`MalwareIncident` or `DDoSIncident`), and updates device health state.
5. **Save Incident Report to File**: Exports executive summary metrics, device status inventories, and complete chronological incident investigation logs to `cyber_incident_report.txt`.
6. **Exit**: Gracefully exits the application.
