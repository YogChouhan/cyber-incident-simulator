#include "../include/Incident.h"
#include <iomanip>

std::string severityToString(IncidentSeverity severity) {
    switch (severity) {
        case IncidentSeverity::LOW:      return "LOW";
        case IncidentSeverity::MEDIUM:   return "MEDIUM";
        case IncidentSeverity::HIGH:     return "HIGH";
        case IncidentSeverity::CRITICAL: return "CRITICAL";
        default:                         return "UNKNOWN";
    }
}

std::string incidentStatusToString(IncidentStatus status) {
    switch (status) {
        case IncidentStatus::ACTIVE:        return "ACTIVE";
        case IncidentStatus::INVESTIGATING: return "INVESTIGATING";
        case IncidentStatus::CONTAINED:     return "CONTAINED";
        case IncidentStatus::RESOLVED:      return "RESOLVED";
        default:                            return "UNKNOWN";
    }
}

// ============================================================================
// SecurityIncident (Abstract Base Class) Implementation
// ============================================================================

SecurityIncident::SecurityIncident(int id, const std::string& title, IncidentSeverity severity,
                                   NetworkDevice* targetDevice, const std::string& timestamp)
    : m_id(id),
      m_title(title),
      m_severity(severity),
      m_status(IncidentStatus::ACTIVE),
      m_timestamp(timestamp),
      m_targetDevice(targetDevice),
      m_actionLog("Incident triggered at " + timestamp + "\n") {}

int SecurityIncident::getId() const {
    return m_id;
}

std::string SecurityIncident::getTitle() const {
    return m_title;
}

IncidentSeverity SecurityIncident::getSeverity() const {
    return m_severity;
}

std::string SecurityIncident::getSeverityString() const {
    return severityToString(m_severity);
}

IncidentStatus SecurityIncident::getStatus() const {
    return m_status;
}

std::string SecurityIncident::getStatusString() const {
    return incidentStatusToString(m_status);
}

std::string SecurityIncident::getTimestamp() const {
    return m_timestamp;
}

NetworkDevice* SecurityIncident::getTargetDevice() const {
    return m_targetDevice;
}

std::string SecurityIncident::getActionLog() const {
    return m_actionLog;
}

void SecurityIncident::setStatus(IncidentStatus status) {
    m_status = status;
}

void SecurityIncident::setTargetDevice(NetworkDevice* target) {
    m_targetDevice = target;
}

void SecurityIncident::appendLog(const std::string& entry) {
    m_actionLog += "  -> " + entry + "\n";
}

// ============================================================================
// MalwareIncident Implementation
// ============================================================================

MalwareIncident::MalwareIncident(int id, const std::string& title, IncidentSeverity severity,
                                 NetworkDevice* targetDevice, const std::string& timestamp,
                                 const std::string& signature, const std::string& infectedProcess)
    : SecurityIncident(id, title, severity, targetDevice, timestamp),
      m_malwareSignature(signature),
      m_infectedProcess(infectedProcess),
      m_isolatedFromNetwork(false),
      m_processTerminated(false) {}

std::string MalwareIncident::getMalwareSignature() const {
    return m_malwareSignature;
}

std::string MalwareIncident::getInfectedProcess() const {
    return m_infectedProcess;
}

std::string MalwareIncident::getIncidentType() const {
    return "Malware Infection (Ransomware / Trojan)";
}

void MalwareIncident::investigate() const {
    std::cout << "\n=======================================================\n"
              << "       INVESTIGATING MALWARE INCIDENT [#" << m_id << "]\n"
              << "=======================================================\n"
              << " Title             : " << m_title << "\n"
              << " Classification    : " << getIncidentType() << "\n"
              << " Severity Level    : " << getSeverityString() << "\n"
              << " Current Status    : " << getStatusString() << "\n"
              << " Timestamp Detected: " << m_timestamp << "\n"
              << " Malware Signature : " << m_malwareSignature << "\n"
              << " Infected Process  : " << m_infectedProcess << " (PID 4421)\n";

    if (m_targetDevice != nullptr) {
        std::cout << " Target Endpoint   : " << m_targetDevice->getHostname()
                  << " (" << m_targetDevice->getIpAddress() << ")\n"
                  << " Target Role       : " << m_targetDevice->getDeviceRole() << "\n"
                  << " Target State      : [" << m_targetDevice->getStatusString() << "]\n\n";

        // Polymorphic invocation of device diagnostics
        m_targetDevice->performDiagnostics();
    } else {
        std::cout << " Target Device     : [Unassigned / None]\n";
    }

    std::cout << "\nForensic Memory Dump & Heuristic Findings:\n"
              << " - Process hooking detected in memory address space.\n"
              << " - Unauthorized encrypted outbound beacons observed.\n"
              << " - Isolation applied: " << (m_isolatedFromNetwork ? "YES" : "NO") << "\n"
              << " - Malicious process terminated: " << (m_processTerminated ? "YES" : "NO") << "\n"
              << "=======================================================\n";
}

void MalwareIncident::printResponseOptions() const {
    std::cout << "\nSelect Remediation Action for Malware Incident #" << m_id << ":\n"
              << " [1] Network Isolation       : Sever device NIC connection to halt lateral movement\n"
              << " [2] Process Termination     : Kill '" << m_infectedProcess << "' and quarantine binaries\n"
              << " [3] Full System Restoration : Restore clean disk image and return device to ONLINE\n"
              << " [4] Cancel                  : Return to main menu\n";
}

bool MalwareIncident::applyResponse(int actionChoice) {
    if (m_targetDevice == nullptr) {
        std::cout << "[ERROR] Cannot apply response: Target device is null.\n";
        return false;
    }

    switch (actionChoice) {
        case 1: {
            m_isolatedFromNetwork = true;
            m_targetDevice->setStatus(DeviceStatus::ISOLATED);
            setStatus(IncidentStatus::CONTAINED);
            appendLog("Host " + m_targetDevice->getHostname() + " isolated from network via virtual VLAN containment.");
            std::cout << "\n[ACTION EXECUTED] Device " << m_targetDevice->getHostname()
                      << " is now ISOLATED. Threat lateral movement stopped.\n";
            return true;
        }
        case 2: {
            m_processTerminated = true;
            appendLog("Process '" + m_infectedProcess + "' killed. Malicious payloads quarantined to vault.");
            std::cout << "\n[ACTION EXECUTED] Process " << m_infectedProcess
                      << " terminated. Registry autostart entries purged.\n";
            if (m_status == IncidentStatus::ACTIVE) {
                setStatus(IncidentStatus::INVESTIGATING);
            }
            return true;
        }
        case 3: {
            if (!m_processTerminated && !m_isolatedFromNetwork) {
                std::cout << "\n[WARNING] Restoring without prior containment or termination is risky.\n"
                          << "Proceeding with emergency golden-image rollback...\n";
            }
            m_targetDevice->setStatus(DeviceStatus::ONLINE);
            setStatus(IncidentStatus::RESOLVED);
            appendLog("Endpoint restored from verified immutable snapshot. Device returned to ONLINE state.");
            std::cout << "\n[ACTION EXECUTED] Device " << m_targetDevice->getHostname()
                      << " restored from backup! Incident marked as RESOLVED.\n";
            return true;
        }
        case 4: {
            std::cout << "Action cancelled. Returning.\n";
            return false;
        }
        default: {
            std::cout << "Invalid action choice.\n";
            return false;
        }
    }
}

std::string MalwareIncident::getDetailedReport() const {
    std::ostringstream ss;
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
// DDoSIncident Implementation
// ============================================================================

DDoSIncident::DDoSIncident(int id, const std::string& title, IncidentSeverity severity,
                           NetworkDevice* targetDevice, const std::string& timestamp,
                           const std::string& attackVector, double trafficVolumeGbps)
    : SecurityIncident(id, title, severity, targetDevice, timestamp),
      m_attackVector(attackVector),
      m_trafficVolumeGbps(trafficVolumeGbps),
      m_trafficScrubbed(false),
      m_rateLimitingEnabled(false) {}

std::string DDoSIncident::getAttackVector() const {
    return m_attackVector;
}

double DDoSIncident::getTrafficVolumeGbps() const {
    return m_trafficVolumeGbps;
}

std::string DDoSIncident::getIncidentType() const {
    return "Distributed Denial of Service (DDoS)";
}

void DDoSIncident::investigate() const {
    std::cout << "\n=======================================================\n"
              << "       INVESTIGATING DDOS INCIDENT [#" << m_id << "]\n"
              << "=======================================================\n"
              << " Title             : " << m_title << "\n"
              << " Classification    : " << getIncidentType() << "\n"
              << " Severity Level    : " << getSeverityString() << "\n"
              << " Current Status    : " << getStatusString() << "\n"
              << " Timestamp Detected: " << m_timestamp << "\n"
              << " Attack Vector     : " << m_attackVector << "\n"
              << " Peak Traffic Load : " << std::fixed << std::setprecision(1)
              << m_trafficVolumeGbps << " Gbps\n";

    if (m_targetDevice != nullptr) {
        std::cout << " Target Asset      : " << m_targetDevice->getHostname()
                  << " (" << m_targetDevice->getIpAddress() << ")\n"
                  << " Asset Role        : " << m_targetDevice->getDeviceRole() << "\n"
                  << " Asset State       : [" << m_targetDevice->getStatusString() << "]\n\n";

        // Polymorphic invocation of device diagnostics
        m_targetDevice->performDiagnostics();
    } else {
        std::cout << " Target Device     : [Unassigned / None]\n";
    }

    std::cout << "\nTelemetry & Traffic Flow Analysis:\n"
              << " - Synchronous ACK/SYN packet anomaly ratio > 8500:1\n"
              << " - Target network interface experiencing massive packet loss and buffer congestion.\n"
              << " - Traffic scrubbing operational : " << (m_trafficScrubbed ? "YES" : "NO") << "\n"
              << " - Upstream rate-limiting enforced: " << (m_rateLimitingEnabled ? "YES" : "NO") << "\n"
              << "=======================================================\n";
}

void DDoSIncident::printResponseOptions() const {
    std::cout << "\nSelect Remediation Action for DDoS Incident #" << m_id << ":\n"
              << " [1] Traffic Scrubbing      : Route ingress traffic through Cloud Anti-DDoS Scrubbing\n"
              << " [2] Rate Limiting & Filter : Enforce ingress packet rate-limits and drop spoofed packets\n"
              << " [3] Flush & Reset Services : Reset socket pools, verify throughput, and mark ONLINE\n"
              << " [4] Cancel                 : Return to main menu\n";
}

bool DDoSIncident::applyResponse(int actionChoice) {
    if (m_targetDevice == nullptr) {
        std::cout << "[ERROR] Cannot apply response: Target device is null.\n";
        return false;
    }

    switch (actionChoice) {
        case 1: {
            m_trafficScrubbed = true;
            m_trafficVolumeGbps *= 0.15; // Drops attack volume by 85%
            setStatus(IncidentStatus::CONTAINED);
            appendLog("Diverted border ingress traffic to Scrubbing Centers. Filtered 85% volumetric junk.");
            std::cout << "\n[ACTION EXECUTED] Traffic scrubbing active! Peak load dropped to "
                      << std::fixed << std::setprecision(1) << m_trafficVolumeGbps << " Gbps.\n";
            return true;
        }
        case 2: {
            m_rateLimitingEnabled = true;
            appendLog("Activated upstream border edge rate-limiting and drop rules for spoofed CIDRs.");
            std::cout << "\n[ACTION EXECUTED] Rate limiting enabled on upstream router interfaces.\n";
            if (m_status == IncidentStatus::ACTIVE) {
                setStatus(IncidentStatus::INVESTIGATING);
            }
            return true;
        }
        case 3: {
            m_targetDevice->setStatus(DeviceStatus::ONLINE);
            setStatus(IncidentStatus::RESOLVED);
            appendLog("Socket pools recycled. Latency normalized. Service restored to healthy ONLINE state.");
            std::cout << "\n[ACTION EXECUTED] Network stack restarted for " << m_targetDevice->getHostname()
                      << ". Device status is ONLINE. Incident marked as RESOLVED.\n";
            return true;
        }
        case 4: {
            std::cout << "Action cancelled. Returning.\n";
            return false;
        }
        default: {
            std::cout << "Invalid action choice.\n";
            return false;
        }
    }
}

std::string DDoSIncident::getDetailedReport() const {
    std::ostringstream ss;
    ss << "========================================================\n"
       << "INCIDENT REPORT: #" << m_id << " - " << m_title << "\n"
       << "Type: " << getIncidentType() << "\n"
       << "Severity: " << getSeverityString() << " | Status: " << getStatusString() << "\n"
       << "Detection Timestamp: " << m_timestamp << "\n"
       << "Attack Vector: " << m_attackVector << "\n"
       << "Observed Peak Load: " << std::fixed << std::setprecision(1) << m_trafficVolumeGbps << " Gbps\n";
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
