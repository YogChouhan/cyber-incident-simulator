#include "../include/Device.h"

std::string deviceStatusToString(DeviceStatus status) {
    switch (status) {
        case DeviceStatus::ONLINE:       return "ONLINE";
        case DeviceStatus::COMPROMISED: return "COMPROMISED";
        case DeviceStatus::UNDER_ATTACK: return "UNDER_ATTACK";
        case DeviceStatus::ISOLATED:     return "ISOLATED";
        case DeviceStatus::OFFLINE:      return "OFFLINE";
        default:                         return "UNKNOWN";
    }
}

// ============================================================================
// NetworkDevice (Abstract Base Class) Implementation
// ============================================================================

NetworkDevice::NetworkDevice(int id, const std::string& hostname, const std::string& ipAddress, DeviceStatus status)
    : m_id(id), m_hostname(hostname), m_ipAddress(ipAddress), m_status(status) {}

int NetworkDevice::getId() const {
    return m_id;
}

std::string NetworkDevice::getHostname() const {
    return m_hostname;
}

std::string NetworkDevice::getIpAddress() const {
    return m_ipAddress;
}

DeviceStatus NetworkDevice::getStatus() const {
    return m_status;
}

std::string NetworkDevice::getStatusString() const {
    return deviceStatusToString(m_status);
}

void NetworkDevice::setStatus(DeviceStatus newStatus) {
    m_status = newStatus;
}

void NetworkDevice::setHostname(const std::string& hostname) {
    m_hostname = hostname;
}

void NetworkDevice::setIpAddress(const std::string& ipAddress) {
    m_ipAddress = ipAddress;
}

// ============================================================================
// Server Implementation
// ============================================================================

Server::Server(int id, const std::string& hostname, const std::string& ipAddress,
               const std::string& serviceType, int activeConnections, DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_serviceType(serviceType),
      m_activeConnections(activeConnections) {}

std::string Server::getServiceType() const {
    return m_serviceType;
}

void Server::setServiceType(const std::string& serviceType) {
    m_serviceType = serviceType;
}

int Server::getActiveConnections() const {
    return m_activeConnections;
}

void Server::setActiveConnections(int count) {
    m_activeConnections = count;
}

std::string Server::getDeviceRole() const {
    return "Enterprise Infrastructure Server";
}

void Server::displayInfo() const {
    std::cout << "[SERVER #" << m_id << "]\n"
              << "  Hostname       : " << m_hostname << "\n"
              << "  IP Address     : " << m_ipAddress << "\n"
              << "  Role           : " << getDeviceRole() << "\n"
              << "  Hosted Service : " << m_serviceType << "\n"
              << "  Active Conns   : " << m_activeConnections << "\n"
              << "  Status         : [" << getStatusString() << "]\n";
}

void Server::performDiagnostics() const {
    std::cout << ">>> Running Server Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
              << "  [1] Verifying systemd daemon for service: " << m_serviceType << "\n"
              << "  [2] Analyzing socket queue (Active TCP/UDP Conns: " << m_activeConnections << ")\n"
              << "  [3] Checking root filesystem inode integrity & log anomalies\n"
              << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}

// ============================================================================
// Workstation Implementation
// ============================================================================

Workstation::Workstation(int id, const std::string& hostname, const std::string& ipAddress,
                         const std::string& assignedUser, const std::string& operatingSystem,
                         DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_assignedUser(assignedUser),
      m_operatingSystem(operatingSystem) {}

std::string Workstation::getAssignedUser() const {
    return m_assignedUser;
}

void Workstation::setAssignedUser(const std::string& user) {
    m_assignedUser = user;
}

std::string Workstation::getOperatingSystem() const {
    return m_operatingSystem;
}

void Workstation::setOperatingSystem(const std::string& os) {
    m_operatingSystem = os;
}

std::string Workstation::getDeviceRole() const {
    return "Employee Client Workstation";
}

void Workstation::displayInfo() const {
    std::cout << "[WORKSTATION #" << m_id << "]\n"
              << "  Hostname       : " << m_hostname << "\n"
              << "  IP Address     : " << m_ipAddress << "\n"
              << "  Role           : " << getDeviceRole() << "\n"
              << "  Assigned User  : " << m_assignedUser << "\n"
              << "  OS Version     : " << m_operatingSystem << "\n"
              << "  Status         : [" << getStatusString() << "]\n";
}

void Workstation::performDiagnostics() const {
    std::cout << ">>> Running Workstation Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
              << "  [1] Verifying Endpoint Detection and Response (EDR) agent\n"
              << "  [2] Auditing logged-in user session for: " << m_assignedUser << "\n"
              << "  [3] Scanning local startup registry keys and task schedulers\n"
              << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}

// ============================================================================
// Firewall Implementation
// ============================================================================

Firewall::Firewall(int id, const std::string& hostname, const std::string& ipAddress,
                   const std::string& inspectionPolicy, int blockedThreats,
                   DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_blockedThreatsCount(blockedThreats),
      m_inspectionPolicy(inspectionPolicy) {}

int Firewall::getBlockedThreatsCount() const {
    return m_blockedThreatsCount;
}

void Firewall::incrementBlockedThreats(int count) {
    m_blockedThreatsCount += count;
}

std::string Firewall::getInspectionPolicy() const {
    return m_inspectionPolicy;
}

void Firewall::setInspectionPolicy(const std::string& policy) {
    m_inspectionPolicy = policy;
}

std::string Firewall::getDeviceRole() const {
    return "Perimeter Security Gateway / Firewall";
}

void Firewall::displayInfo() const {
    std::cout << "[FIREWALL #" << m_id << "]\n"
              << "  Hostname       : " << m_hostname << "\n"
              << "  IP Address     : " << m_ipAddress << "\n"
              << "  Role           : " << getDeviceRole() << "\n"
              << "  Inspection ACL : " << m_inspectionPolicy << "\n"
              << "  Blocked Threats: " << m_blockedThreatsCount << "\n"
              << "  Status         : [" << getStatusString() << "]\n";
}

void Firewall::performDiagnostics() const {
    std::cout << ">>> Running Firewall Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
              << "  [1] Checking SPI (Stateful Packet Inspection) connection table capacity\n"
              << "  [2] Evaluating policy rule enforcement: " << m_inspectionPolicy << "\n"
              << "  [3] Total dropped/blocked malicious packets logged: " << m_blockedThreatsCount << "\n"
              << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}
