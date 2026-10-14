#ifndef INCIDENT_H
#define INCIDENT_H

#include "Device.h"
#include <string>
#include <iostream>
#include <sstream>

/**
 * @enum IncidentSeverity
 * @brief Severity level classification according to cybersecurity frameworks.
 */
enum class IncidentSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

/**
 * @enum IncidentStatus
 * @brief Current triage and lifecycle state of the security incident.
 */
enum class IncidentStatus {
    ACTIVE,
    INVESTIGATING,
    CONTAINED,
    RESOLVED
};

/**
 * @brief Helper utility functions for enum string conversion.
 */
std::string severityToString(IncidentSeverity severity);
std::string incidentStatusToString(IncidentStatus status);

/**
 * @class SecurityIncident
 * @brief Abstract Base Class representing an ongoing or historical security event.
 * Demonstrates: Non-owning pointer reference to target device, pure virtual functions.
 */
class SecurityIncident {
protected:
    int m_id;
    std::string m_title;
    IncidentSeverity m_severity;
    IncidentStatus m_status;
    std::string m_timestamp;
    NetworkDevice* m_targetDevice; // Non-owning raw pointer to affected target
    std::string m_actionLog;

public:
    SecurityIncident(int id, const std::string& title, IncidentSeverity severity,
                     NetworkDevice* targetDevice, const std::string& timestamp);
    virtual ~SecurityIncident() = default;

    // Getters and Setters (Encapsulation)
    int getId() const;
    std::string getTitle() const;
    IncidentSeverity getSeverity() const;
    std::string getSeverityString() const;
    IncidentStatus getStatus() const;
    std::string getStatusString() const;
    std::string getTimestamp() const;
    NetworkDevice* getTargetDevice() const;
    std::string getActionLog() const;

    void setStatus(IncidentStatus status);
    void setTargetDevice(NetworkDevice* target);
    void appendLog(const std::string& entry);

    // Pure Virtual Functions (Polymorphism & Abstraction)
    virtual void investigate() const = 0;
    virtual void printResponseOptions() const = 0;
    virtual bool applyResponse(int actionChoice) = 0;
    virtual std::string getIncidentType() const = 0;
    virtual std::string getDetailedReport() const = 0;
};

/**
 * @class MalwareIncident
 * @brief Derived class simulating malware, trojan, or ransomware infections.
 */
class MalwareIncident : public SecurityIncident {
private:
    std::string m_malwareSignature;
    std::string m_infectedProcess;
    bool m_isolatedFromNetwork;
    bool m_processTerminated;

public:
    MalwareIncident(int id, const std::string& title, IncidentSeverity severity,
                    NetworkDevice* targetDevice, const std::string& timestamp,
                    const std::string& signature, const std::string& infectedProcess);
    ~MalwareIncident() override = default;

    std::string getMalwareSignature() const;
    std::string getInfectedProcess() const;

    // Overridden Virtual Functions
    void investigate() const override;
    void printResponseOptions() const override;
    bool applyResponse(int actionChoice) override;
    std::string getIncidentType() const override;
    std::string getDetailedReport() const override;
};

/**
 * @class DDoSIncident
 * @brief Derived class simulating Distributed Denial of Service volumetric and protocol attacks.
 */
class DDoSIncident : public SecurityIncident {
private:
    std::string m_attackVector;
    double m_trafficVolumeGbps;
    bool m_trafficScrubbed;
    bool m_rateLimitingEnabled;

public:
    DDoSIncident(int id, const std::string& title, IncidentSeverity severity,
                 NetworkDevice* targetDevice, const std::string& timestamp,
                 const std::string& attackVector, double trafficVolumeGbps);
    ~DDoSIncident() override = default;

    std::string getAttackVector() const;
    double getTrafficVolumeGbps() const;

    // Overridden Virtual Functions
    void investigate() const override;
    void printResponseOptions() const override;
    bool applyResponse(int actionChoice) override;
    std::string getIncidentType() const override;
    std::string getDetailedReport() const override;
};

#endif // INCIDENT_H
