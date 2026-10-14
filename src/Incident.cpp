#include "Incident.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

using namespace std;

// Converts an IncidentSeverity enum to a readable string
string severityToString(IncidentSeverity severity) {
    switch (severity) {
        case IncidentSeverity::LOW:      return "LOW";
        case IncidentSeverity::MEDIUM:   return "MEDIUM";
        case IncidentSeverity::HIGH:     return "HIGH";
        case IncidentSeverity::CRITICAL: return "CRITICAL";
        default:                         return "UNKNOWN";
    }
}

// Converts an IncidentStatus enum to a readable string
string incidentStatusToString(IncidentStatus status) {
    switch (status) {
        case IncidentStatus::ACTIVE:        return "ACTIVE";
        case IncidentStatus::INVESTIGATING: return "INVESTIGATING";
        case IncidentStatus::CONTAINED:     return "CONTAINED";
        case IncidentStatus::RESOLVED:      return "RESOLVED";
        default:                            return "UNKNOWN";
    }
}

// ============================================================================
// SecurityIncident (Abstract Base Class)
// ============================================================================

// Base constructor initializes common incident metadata and non-owning target device pointer
SecurityIncident::SecurityIncident(int id, const string& title, IncidentSeverity severity,
                                   NetworkDevice* targetDevice, const string& timestamp)
    : m_id(id),
      m_title(title),
      m_severity(severity),
      m_status(IncidentStatus::ACTIVE),
      m_timestamp(timestamp),
      m_targetDevice(targetDevice),
      m_actionLog("Incident triggered at " + timestamp + "\n") {}

// Returns the unique incident ID
int SecurityIncident::getId() const {
    return m_id;
}

// Returns the title or short summary of the incident
string SecurityIncident::getTitle() const {
    return m_title;
}

// Returns the severity enum value
IncidentSeverity SecurityIncident::getSeverity() const {
    return m_severity;
}

// Returns the severity as a text string
string SecurityIncident::getSeverityString() const {
    return severityToString(m_severity);
}

// Returns the current status enum value of the incident
IncidentStatus SecurityIncident::getStatus() const {
    return m_status;
}

// Returns the current status as a text string
string SecurityIncident::getStatusString() const {
    return incidentStatusToString(m_status);
}

// Returns the timestamp when the incident was detected
string SecurityIncident::getTimestamp() const {
    return m_timestamp;
}

// Returns the non-owning raw pointer to the affected target device
NetworkDevice* SecurityIncident::getTargetDevice() const {
    return m_targetDevice;
}

// Returns the history log of mitigation actions taken
string SecurityIncident::getActionLog() const {
    return m_actionLog;
}

// Updates the lifecycle status of the incident
void SecurityIncident::setStatus(IncidentStatus status) {
    m_status = status;
}

// Sets or reassigns the target device reference
void SecurityIncident::setTargetDevice(NetworkDevice* target) {
    m_targetDevice = target;
}

// Appends an audit note to the action history log
void SecurityIncident::appendLog(const string& entry) {
    m_actionLog += "  -> " + entry + "\n";
}

// ============================================================================
// MalwareIncident (Derived Class)
// ============================================================================

// Constructor initializes base attributes plus malware category, signature, and infected process
MalwareIncident::MalwareIncident(int id, const string& title, IncidentSeverity severity,
                                 NetworkDevice* targetDevice, const string& timestamp,
                                 const string& category, const string& signature,
                                 const string& infectedProcess)
    : SecurityIncident(id, title, severity, targetDevice, timestamp),
      m_category(category),
      m_malwareSignature(signature),
      m_infectedProcess(infectedProcess),
      m_isolatedFromNetwork(false),
      m_processTerminated(false) {}

// Returns the malware category (e.g., Ransomware, Infostealer / Spyware)
string MalwareIncident::getCategory() const {
    return m_category;
}

// Returns the detected antivirus/EDR signature name
string MalwareIncident::getMalwareSignature() const {
    return m_malwareSignature;
}

// Returns the malicious process or executable name
string MalwareIncident::getInfectedProcess() const {
    return m_infectedProcess;
}

// Returns the dynamic incident category description
string MalwareIncident::getIncidentType() const {
    return m_category;
}

// Displays detailed forensic investigation data and triggers device diagnostics polymorphically
void MalwareIncident::investigate() const {
    cout << "\n=======================================================\n"
         << "       INVESTIGATING MALWARE INCIDENT [#" << m_id << "]\n"
         << "=======================================================\n"
         << " Title             : " << m_title << "\n"
         << " Classification    : " << getIncidentType() << "\n"
         << " Severity Level    : " << getSeverityString() << "\n"
         << " Current Status    : " << getStatusString() << "\n"
         << " Timestamp Detected: " << m_timestamp << "\n"
         << " Malware Signature : " << m_malwareSignature << "\n"
         << " Infected Process  : " << m_infectedProcess << "\n";

    if (m_targetDevice != nullptr) {
        cout << " Target Endpoint   : " << m_targetDevice->getHostname()
             << " (" << m_targetDevice->getIpAddress() << ")\n"
             << " Target Role       : " << m_targetDevice->getDeviceRole() << "\n"
             << " Target State      : [" << m_targetDevice->getStatusString() << "]\n\n";

        // Polymorphic invocation of device diagnostics
        m_targetDevice->performDiagnostics();
    } else {
        cout << " Target Device     : [Unassigned / None]\n";
    }

    cout << "\nForensic Memory Dump & Heuristic Findings:\n"
         << " - Process hooking detected in memory address space.\n"
         << " - Unauthorized encrypted outbound beacons observed.\n"
         << " - Isolation applied: " << (m_isolatedFromNetwork ? "YES" : "NO") << "\n"
         << " - Malicious process terminated: " << (m_processTerminated ? "YES" : "NO") << "\n"
         << "=======================================================\n";
}

// Prints available remediation choices for malware
void MalwareIncident::printResponseOptions() const {
    cout << "\nSelect Remediation Action for Malware Incident #" << m_id << ":\n"
         << " [1] Network Isolation       : Sever device NIC connection to halt lateral movement\n"
         << " [2] Process Termination     : Kill '" << m_infectedProcess << "' and quarantine binaries\n"
         << " [3] Full System Restoration : Restore clean disk image and return device to ONLINE\n"
         << " [4] Cancel                  : Return to main menu\n";
}

// Applies the selected response action and updates target device status
bool MalwareIncident::applyResponse(int actionChoice) {
    // Check if incident is already resolved
    if (m_status == IncidentStatus::RESOLVED) {
        cout << "\nThis incident is already resolved.\n";
        return false;
    }

    if (m_targetDevice == nullptr) {
        cout << "[ERROR] Cannot apply response: Target device is null.\n";
        return false;
    }

    switch (actionChoice) {
        case 1: {
            if (m_isolatedFromNetwork) {
                cout << "\nDevice is already isolated from the network.\n";
                return false;
            }
            m_isolatedFromNetwork = true;
            m_targetDevice->setStatus(DeviceStatus::ISOLATED);
            setStatus(IncidentStatus::CONTAINED);
            appendLog("Host " + m_targetDevice->getHostname() + " isolated from network via virtual VLAN containment.");
            cout << "\n[ACTION EXECUTED] Device " << m_targetDevice->getHostname()
                 << " is now ISOLATED. Threat lateral movement stopped.\n";
            return true;
        }
        case 2: {
            if (m_processTerminated) {
                cout << "\nMalicious process has already been terminated.\n";
                return false;
            }
            m_processTerminated = true;
            appendLog("Process '" + m_infectedProcess + "' killed. Malicious payloads quarantined to vault.");
            cout << "\n[ACTION EXECUTED] Process " << m_infectedProcess
                 << " terminated. Registry autostart entries purged.\n";
            if (m_status == IncidentStatus::ACTIVE) {
                setStatus(IncidentStatus::INVESTIGATING);
            }
            return true;
        }
        case 3: {
            if (!m_processTerminated && !m_isolatedFromNetwork) {
                cout << "\n[WARNING] Restoring without prior containment or termination is risky.\n"
                     << "Proceeding with emergency golden-image rollback...\n";
            }
            m_targetDevice->setStatus(DeviceStatus::ONLINE);
            setStatus(IncidentStatus::RESOLVED);
            appendLog("Endpoint restored from verified immutable snapshot. Device returned to ONLINE state.");
            cout << "\n[ACTION EXECUTED] Device " << m_targetDevice->getHostname()
                 << " restored from backup! Incident marked as RESOLVED.\n";
            return true;
        }
        case 4: {
            cout << "Action cancelled. Returning.\n";
            return false;
        }
        default: {
            cout << "Invalid action choice.\n";
            return false;
        }
    }
}

// Generates a complete text report for this malware incident
string MalwareIncident::getDetailedReport() const {
    ostringstream ss;
    ss << "========================================================\n"
       << "INCIDENT REPORT: #" << m_id << " - " << m_title << "\n"
       << "Type: " << getIncidentType() << "\n"
       << "Severity: " << getSeverityString() << " | Status: " << getStatusString() << "\n"
       << "Detection Timestamp: " << m_timestamp << "\n"
       << "Malware Signature: " << m_malwareSignature << "\n"
       << "Associated Process: " << m_infectedProcess << "\n";
    if (m_targetDevice != nullptr) {
        ss << "Affected Device: " << m_targetDevice->getHostname()
           << " [" << m_targetDevice->getIpAddress() << "] Role: "
           << m_targetDevice->getDeviceRole() << " | Current Status: "
           << m_targetDevice->getStatusString() << "\n";
    }
    ss << "Action History Log:\n" << m_actionLog
       << "========================================================\n";
    return ss.str();
}

// ============================================================================
// DDoSIncident (Derived Class)
// ============================================================================

// Constructor initializes base attributes plus DDoS attack vector and volume
DDoSIncident::DDoSIncident(int id, const string& title, IncidentSeverity severity,
                           NetworkDevice* targetDevice, const string& timestamp,
                           const string& attackVector, double trafficVolumeGbps)
    : SecurityIncident(id, title, severity, targetDevice, timestamp),
      m_attackVector(attackVector),
      m_trafficVolumeGbps(trafficVolumeGbps),
      m_trafficScrubbed(false),
      m_rateLimitingEnabled(false) {}

// Returns the detected DDoS vector type
string DDoSIncident::getAttackVector() const {
    return m_attackVector;
}

// Returns peak observed traffic load in Gbps
double DDoSIncident::getTrafficVolumeGbps() const {
    return m_trafficVolumeGbps;
}

// Returns the incident category name
string DDoSIncident::getIncidentType() const {
    return "Distributed Denial of Service (DDoS)";
}

// Displays telemetry analysis and triggers target device diagnostics polymorphically
void DDoSIncident::investigate() const {
    cout << "\n=======================================================\n"
         << "       INVESTIGATING DDOS INCIDENT [#" << m_id << "]\n"
         << "=======================================================\n"
         << " Title             : " << m_title << "\n"
         << " Classification    : " << getIncidentType() << "\n"
         << " Severity Level    : " << getSeverityString() << "\n"
         << " Current Status    : " << getStatusString() << "\n"
         << " Timestamp Detected: " << m_timestamp << "\n"
         << " Attack Vector     : " << m_attackVector << "\n"
         << " Peak Traffic Load : " << fixed << setprecision(1)
         << m_trafficVolumeGbps << " Gbps\n";

    if (m_targetDevice != nullptr) {
        cout << " Target Asset      : " << m_targetDevice->getHostname()
             << " (" << m_targetDevice->getIpAddress() << ")\n"
             << " Asset Role        : " << m_targetDevice->getDeviceRole() << "\n"
             << " Asset State       : [" << m_targetDevice->getStatusString() << "]\n\n";

        // Polymorphic invocation of device diagnostics
        m_targetDevice->performDiagnostics();
    } else {
        cout << " Target Device     : [Unassigned / None]\n";
    }

    cout << "\nTelemetry & Traffic Flow Analysis:\n"
         << " - Synchronous ACK/SYN packet anomaly ratio > 8500:1\n"
         << " - Target network interface experiencing massive packet loss and buffer congestion.\n"
         << " - Traffic scrubbing operational : " << (m_trafficScrubbed ? "YES" : "NO") << "\n"
         << " - Upstream rate-limiting enforced: " << (m_rateLimitingEnabled ? "YES" : "NO") << "\n"
         << "=======================================================\n";
}

// Prints available remediation choices for DDoS attacks
void DDoSIncident::printResponseOptions() const {
    cout << "\nSelect Remediation Action for DDoS Incident #" << m_id << ":\n"
         << " [1] Traffic Scrubbing      : Route ingress traffic through Cloud Anti-DDoS Scrubbing\n"
         << " [2] Rate Limiting & Filter : Enforce ingress packet rate-limits and drop spoofed packets\n"
         << " [3] Flush & Reset Services : Reset socket pools, verify throughput, and mark ONLINE\n"
         << " [4] Cancel                 : Return to main menu\n";
}

// Applies the selected DDoS remediation action and updates device status
bool DDoSIncident::applyResponse(int actionChoice) {
    // Check if incident is already resolved
    if (m_status == IncidentStatus::RESOLVED) {
        cout << "\nThis incident is already resolved.\n";
        return false;
    }

    if (m_targetDevice == nullptr) {
        cout << "[ERROR] Cannot apply response: Target device is null.\n";
        return false;
    }

    switch (actionChoice) {
        case 1: {
            if (m_trafficScrubbed) {
                cout << "\nTraffic scrubbing is already active.\n";
                return false;
            }
            m_trafficScrubbed = true;
            m_trafficVolumeGbps *= 0.15; // Drops attack volume by 85%
            setStatus(IncidentStatus::CONTAINED);
            appendLog("Diverted border ingress traffic to Scrubbing Centers. Filtered 85% volumetric junk.");
            cout << "\n[ACTION EXECUTED] Traffic scrubbing active! Peak load dropped to "
                 << fixed << setprecision(1) << m_trafficVolumeGbps << " Gbps.\n";
            return true;
        }
        case 2: {
            if (m_rateLimitingEnabled) {
                cout << "\nRate limiting is already active.\n";
                return false;
            }
            m_rateLimitingEnabled = true;
            appendLog("Activated upstream border edge rate-limiting and drop rules for spoofed CIDRs.");
            cout << "\n[ACTION EXECUTED] Rate limiting enabled on upstream router interfaces.\n";
            if (m_status == IncidentStatus::ACTIVE) {
                setStatus(IncidentStatus::INVESTIGATING);
            }
            return true;
        }
        case 3: {
            if (!m_trafficScrubbed && !m_rateLimitingEnabled) {
                cout << "\n[WARNING] Resetting network stack without traffic scrubbing or rate limiting is risky.\n"
                     << "Proceeding with emergency socket pool flush...\n";
            }
            m_targetDevice->setStatus(DeviceStatus::ONLINE);
            setStatus(IncidentStatus::RESOLVED);
            appendLog("Socket pools recycled. Latency normalized. Service restored to healthy ONLINE state.");
            cout << "\n[ACTION EXECUTED] Network stack restarted for " << m_targetDevice->getHostname()
                 << ". Device status is ONLINE. Incident marked as RESOLVED.\n";
            return true;
        }
        case 4: {
            cout << "Action cancelled. Returning.\n";
            return false;
        }
        default: {
            cout << "Invalid action choice.\n";
            return false;
        }
    }
}

// Generates a complete text report for this DDoS incident
string DDoSIncident::getDetailedReport() const {
    ostringstream ss;
    ss << "========================================================\n"
       << "INCIDENT REPORT: #" << m_id << " - " << m_title << "\n"
       << "Type: " << getIncidentType() << "\n"
       << "Severity: " << getSeverityString() << " | Status: " << getStatusString() << "\n"
       << "Detection Timestamp: " << m_timestamp << "\n"
       << "Attack Vector: " << m_attackVector << "\n"
       << "Observed Peak Load: " << fixed << setprecision(1) << m_trafficVolumeGbps << " Gbps\n";
    if (m_targetDevice != nullptr) {
        ss << "Affected Device: " << m_targetDevice->getHostname()
           << " [" << m_targetDevice->getIpAddress() << "] Role: "
           << m_targetDevice->getDeviceRole() << " | Current Status: "
           << m_targetDevice->getStatusString() << "\n";
    }
    ss << "Action History Log:\n" << m_actionLog
       << "========================================================\n";
    return ss.str();
}
