# Cyber Incident Response Simulator

A modular, standard **C++17** simulation environment designed for cybersecurity operations and incident handling, built to demonstrate modern Object-Oriented Programming (OOP) paradigms for university academic submissions.

---

## 1. Project Directory Structure

```
CyberIncidentSimulator/
├── CMakeLists.txt
├── README.md
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

## 2. Core OOP Principles Demonstrated

| Concept | Implementation Details |
|---|---|
| **Encapsulation** | Private/protected member variables across all classes with controlled accessor (`getters`) and mutator (`setters`) methods. Internal states cannot be mutated arbitrarily. |
| **Inheritance** | Base class `NetworkDevice` inherited by `Server`, `Workstation`, and `Firewall`. Base class `SecurityIncident` inherited by `MalwareIncident` and `DDoSIncident`. |
| **Abstract Classes** | `NetworkDevice` contains pure virtual functions (`getDeviceRole() = 0`, `displayInfo() = 0`, `performDiagnostics() = 0`). `SecurityIncident` contains pure virtual functions (`investigate() = 0`, `applyResponse() = 0`, `printResponseOptions() = 0`, `getIncidentType() = 0`, `getDetailedReport() = 0`). Neither base class can be directly instantiated. |
| **Polymorphism & Dynamic Dispatch** | Virtual destructors ensure safe polymorphic cleanup. Virtual functions are overridden with `override`. When investigating incidents, runtime dynamic dispatch selects the correct subclass method (`MalwareIncident::investigate()` vs `DDoSIncident::investigate()`) and transitively invokes `targetDevice->performDiagnostics()`. |
| **Memory Management** | Device and Incident lifecycles are managed by the container via `std::vector<std::unique_ptr<NetworkDevice>>` and `std::vector<std::unique_ptr<SecurityIncident>>`. Ownership is single and explicit. Raw pointers (`NetworkDevice* targetDevice`) are strictly used as **non-owning references**. |
| **File Handling** | Reports are generated using standard `<fstream>` (`std::ofstream`) to export a structured audit log to `cyber_incident_report.txt`. |
| **Standard C++17** | Uses strictly standard headers (`<iostream>`, `<memory>`, `<vector>`, `<string>`, `<random>`, `<chrono>`, `<ctime>`, `<fstream>`). No platform-dependent headers (zero `<windows.h>` dependencies). |

---

## 3. How to Build and Run

### Target Environment
- **Compiler**: MinGW-w64 GCC (supporting C++17 or higher)
- **Editor**: Visual Studio Code (Terminal / Tasks)

### Option A: Direct Compilation with MinGW GCC (Quickest)
Open the terminal inside the `CyberIncidentSimulator` directory and run:

```bash
g++ -std=c++17 -Wall -Wextra -pedantic -Iinclude src/main.cpp src/Device.cpp src/Incident.cpp src/Simulator.cpp -o CyberIncidentSimulator.exe
```

Run the application:
```bash
./CyberIncidentSimulator.exe
```

### Option B: Using CMake & Ninja / MinGW Makefiles
```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
./CyberIncidentSimulator.exe
```

---

## 4. Application Workflow & Features

1. **View Network Status**: Displays all registered hosts, IP addresses, operational roles, and health statuses (`ONLINE`, `COMPROMISED`, `UNDER_ATTACK`, `ISOLATED`, `OFFLINE`). Allows detailed polymorphic diagnostic scans of any device.
2. **View Active Incidents**: Summarizes the queue of active and contained security incidents, their threat severity, and targeted endpoints.
3. **Investigate & Respond to Incident**: 
   - Displays attack forensic telemetry.
   - Traces device hardware/software diagnostics via dynamic dispatch.
   - Offers context-specific containment actions:
     - *Malware*: Network Isolation, Process Termination & Quarantine, Clean Image Snapshot Rollback.
     - *DDoS*: Cloud Traffic Scrubbing, Subnet Rate-Limiting / Null-Routing, Connection Table Flush & Reset.
4. **Generate Random Incident**: Randomly targets an online device, creates a new incident (`MalwareIncident` or `DDoSIncident`), and transitions device state dynamically.
5. **Save Incident Report to File**: Exports executive summary metrics, device status inventories, and complete chronological incident investigation logs to `cyber_incident_report.txt`.
