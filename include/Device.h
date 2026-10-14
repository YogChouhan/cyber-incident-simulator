#ifndef DEVICE_H
#define DEVICE_H

#include <string>

/**
 * @enum DeviceStatus
 * Represents the operational and security status of a network device.
 */
enum class DeviceStatus {
    ONLINE,
    COMPROMISED,
    UNDER_ATTACK,
    ISOLATED,
    OFFLINE
};

// Helper utility to convert DeviceStatus enum to a readable string
std::string deviceStatusToString(DeviceStatus status);

/**
 * @class NetworkDevice
 * Abstract base class representing a generic device on the network.
 */
class NetworkDevice {
protected:
    int m_id;
    std::string m_hostname;
    std::string m_ipAddress;
    DeviceStatus m_status;

public:
    NetworkDevice(int id, const std::string& hostname, const std::string& ipAddress, DeviceStatus status = DeviceStatus::ONLINE);
    virtual ~NetworkDevice() = default;

    // Getters and Setters
    int getId() const;
    std::string getHostname() const;
    std::string getIpAddress() const;
    DeviceStatus getStatus() const;
    std::string getStatusString() const;

    void setStatus(DeviceStatus newStatus);
    void setHostname(const std::string& hostname);
    void setIpAddress(const std::string& ipAddress);

    // Pure virtual functions that derived classes must implement
    virtual std::string getDeviceRole() const = 0;
    virtual void displayInfo() const = 0;
    virtual void performDiagnostics() const = 0;
};

/**
 * @class Server
 * Derived class representing servers (e.g., Database, Web Server).
 */
class Server : public NetworkDevice {
private:
    std::string m_serviceType;
    int m_activeConnections;

public:
    Server(int id, const std::string& hostname, const std::string& ipAddress,
           const std::string& serviceType, int activeConnections = 0,
           DeviceStatus status = DeviceStatus::ONLINE);
    ~Server() override = default;

    std::string getServiceType() const;
    void setServiceType(const std::string& serviceType);

    int getActiveConnections() const;
    void setActiveConnections(int count);

    // Overridden virtual functions
    std::string getDeviceRole() const override;
    void displayInfo() const override;
    void performDiagnostics() const override;
};

/**
 * @class Workstation
 * Derived class representing user client machines.
 */
class Workstation : public NetworkDevice {
private:
    std::string m_assignedUser;
    std::string m_operatingSystem;

public:
    Workstation(int id, const std::string& hostname, const std::string& ipAddress,
                const std::string& assignedUser, const std::string& operatingSystem,
                DeviceStatus status = DeviceStatus::ONLINE);
    ~Workstation() override = default;

    std::string getAssignedUser() const;
    void setAssignedUser(const std::string& user);

    std::string getOperatingSystem() const;
    void setOperatingSystem(const std::string& os);

    // Overridden virtual functions
    std::string getDeviceRole() const override;
    void displayInfo() const override;
    void performDiagnostics() const override;
};

/**
 * @class Firewall
 * Derived class representing network perimeter firewalls.
 */
class Firewall : public NetworkDevice {
private:
    int m_blockedThreatsCount;
    std::string m_inspectionPolicy;

public:
    Firewall(int id, const std::string& hostname, const std::string& ipAddress,
             const std::string& inspectionPolicy, int blockedThreats = 0,
             DeviceStatus status = DeviceStatus::ONLINE);
    ~Firewall() override = default;

    int getBlockedThreatsCount() const;
    void incrementBlockedThreats(int count = 1);

    std::string getInspectionPolicy() const;
    void setInspectionPolicy(const std::string& policy);

    // Overridden virtual functions
    std::string getDeviceRole() const override;
    void displayInfo() const override;
    void performDiagnostics() const override;
};

#endif // DEVICE_H
