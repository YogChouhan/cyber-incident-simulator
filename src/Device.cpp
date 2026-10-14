#include "Device.h"
#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

// Converts a DeviceStatus enum value into a readable string for display
string deviceStatusToString(DeviceStatus status) {
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
// NetworkDevice (Abstract Base Class)
// ============================================================================

// Base constructor initializes common device attributes
NetworkDevice::NetworkDevice(int id, const string& hostname, const string& ipAddress, DeviceStatus status)
    : m_id(id), m_hostname(hostname), m_ipAddress(ipAddress), m_status(status) {}

// Returns the unique numeric ID of the device
int NetworkDevice::getId() const {
    return m_id;
}

// Returns the device hostname
string NetworkDevice::getHostname() const {
    return m_hostname;
}

// Returns the IP address of the device
string NetworkDevice::getIpAddress() const {
    return m_ipAddress;
}

// Returns the current status enum value of the device
DeviceStatus NetworkDevice::getStatus() const {
    return m_status;
}

// Returns the current status as a human-readable text string
string NetworkDevice::getStatusString() const {
    return deviceStatusToString(m_status);
}

// Updates the operational status of the device
void NetworkDevice::setStatus(DeviceStatus newStatus) {
    m_status = newStatus;
}

// Updates the hostname of the device
void NetworkDevice::setHostname(const string& hostname) {
    m_hostname = hostname;
}

// Updates the IP address of the device
void NetworkDevice::setIpAddress(const string& ipAddress) {
    m_ipAddress = ipAddress;
}

// ============================================================================
// Server (Derived Class)
// ============================================================================

// Constructor initializes base attributes plus server-specific service and connections
Server::Server(int id, const string& hostname, const string& ipAddress,
               const string& serviceType, int activeConnections, DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_serviceType(serviceType),
      m_activeConnections(activeConnections) {}

// Returns the type of service running on the server
string Server::getServiceType() const {
    return m_serviceType;
}

// Sets the service type running on this server
void Server::setServiceType(const string& serviceType) {
    m_serviceType = serviceType;
}

// Returns the current number of active TCP connections
int Server::getActiveConnections() const {
    return m_activeConnections;
}

// Updates the count of active connections
void Server::setActiveConnections(int count) {
    m_activeConnections = count;
}

// Returns the descriptive role name for this server
string Server::getDeviceRole() const {
    return "Enterprise Infrastructure Server";
}

// Prints detailed specifications and state of this server
void Server::displayInfo() const {
    cout << "[SERVER #" << m_id << "]\n"
         << "  Hostname       : " << m_hostname << "\n"
         << "  IP Address     : " << m_ipAddress << "\n"
         << "  Role           : " << getDeviceRole() << "\n"
         << "  Hosted Service : " << m_serviceType << "\n"
         << "  Active Conns   : " << m_activeConnections << "\n"
         << "  Status         : [" << getStatusString() << "]\n";
}

// Runs simulated service and socket diagnostic checks on the server
void Server::performDiagnostics() const {
    cout << ">>> Running Server Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
         << "  [1] Verifying systemd daemon for service: " << m_serviceType << "\n"
         << "  [2] Analyzing socket queue (Active TCP/UDP Conns: " << m_activeConnections << ")\n"
         << "  [3] Checking root filesystem inode integrity & log anomalies\n"
         << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}

// ============================================================================
// Workstation (Derived Class)
// ============================================================================

// Constructor initializes base attributes plus assigned user and operating system
Workstation::Workstation(int id, const string& hostname, const string& ipAddress,
                         const string& assignedUser, const string& operatingSystem,
                         DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_assignedUser(assignedUser),
      m_operatingSystem(operatingSystem) {}

// Returns the name of the assigned user
string Workstation::getAssignedUser() const {
    return m_assignedUser;
}

// Updates the assigned user for this workstation
void Workstation::setAssignedUser(const string& user) {
    m_assignedUser = user;
}

// Returns the installed operating system name
string Workstation::getOperatingSystem() const {
    return m_operatingSystem;
}

// Updates the installed operating system name
void Workstation::setOperatingSystem(const string& os) {
    m_operatingSystem = os;
}

// Returns the role description for this workstation
string Workstation::getDeviceRole() const {
    return "Employee Client Workstation";
}

// Prints detailed information about this workstation
void Workstation::displayInfo() const {
    cout << "[WORKSTATION #" << m_id << "]\n"
         << "  Hostname       : " << m_hostname << "\n"
         << "  IP Address     : " << m_ipAddress << "\n"
         << "  Role           : " << getDeviceRole() << "\n"
         << "  Assigned User  : " << m_assignedUser << "\n"
         << "  OS Version     : " << m_operatingSystem << "\n"
         << "  Status         : [" << getStatusString() << "]\n";
}

// Runs simulated EDR and user session diagnostics on the workstation
void Workstation::performDiagnostics() const {
    cout << ">>> Running Workstation Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
         << "  [1] Verifying Endpoint Detection and Response (EDR) agent\n"
         << "  [2] Auditing logged-in user session for: " << m_assignedUser << "\n"
         << "  [3] Scanning local startup registry keys and task schedulers\n"
         << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}

// ============================================================================
// Firewall (Derived Class)
// ============================================================================

// Constructor initializes base attributes plus firewall policy and blocked threats count
Firewall::Firewall(int id, const string& hostname, const string& ipAddress,
                   const string& inspectionPolicy, int blockedThreats,
                   DeviceStatus status)
    : NetworkDevice(id, hostname, ipAddress, status),
      m_blockedThreatsCount(blockedThreats),
      m_inspectionPolicy(inspectionPolicy) {}

// Returns the total number of threats blocked by this firewall
int Firewall::getBlockedThreatsCount() const {
    return m_blockedThreatsCount;
}

// Increments the counter of blocked malicious packets
void Firewall::incrementBlockedThreats(int count) {
    m_blockedThreatsCount += count;
}

// Returns the active packet inspection policy
string Firewall::getInspectionPolicy() const {
    return m_inspectionPolicy;
}

// Updates the active packet inspection policy
void Firewall::setInspectionPolicy(const string& policy) {
    m_inspectionPolicy = policy;
}

// Returns the role description for this firewall
string Firewall::getDeviceRole() const {
    return "Perimeter Security Gateway / Firewall";
}

// Prints detailed firewall configuration and packet counters
void Firewall::displayInfo() const {
    cout << "[FIREWALL #" << m_id << "]\n"
         << "  Hostname       : " << m_hostname << "\n"
         << "  IP Address     : " << m_ipAddress << "\n"
         << "  Role           : " << getDeviceRole() << "\n"
         << "  Inspection ACL : " << m_inspectionPolicy << "\n"
         << "  Blocked Threats: " << m_blockedThreatsCount << "\n"
         << "  Status         : [" << getStatusString() << "]\n";
}

// Runs simulated stateful inspection table and dropped packet diagnostics
void Firewall::performDiagnostics() const {
    cout << ">>> Running Firewall Diagnostics on " << m_hostname << " (" << m_ipAddress << ")...\n"
         << "  [1] Checking SPI (Stateful Packet Inspection) connection table capacity\n"
         << "  [2] Evaluating policy rule enforcement: " << m_inspectionPolicy << "\n"
         << "  [3] Total dropped/blocked malicious packets logged: " << m_blockedThreatsCount << "\n"
         << "  [4] Health assessment: Current device state is [" << getStatusString() << "]\n";
}
