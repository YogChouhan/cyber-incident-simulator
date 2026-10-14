#ifndef INCIDENT_H
#define INCIDENT_H

#include "Device.h"
#include <string>
#include <sstream>

/**
 * @enum IncidentSeverity
 * Severity levels for classified security incidents.
 */
enum class IncidentSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

/**
 * @enum IncidentStatus
 * Lifecycle stages of a security incident.
 */
enum class IncidentStatus {
    ACTIVE,
    INVESTIGATING,
    CONTAINED,
    RESOLVED
};

// Helper utility functions for enum to string conversions
std::string severityToString(IncidentSeverity severity);
std::string incidentStatusToString(IncidentStatus status);

/**
 * @class SecurityIncident
 * Abstract base class representing a generic cybersecurity incident.
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

    // Getters and Setters
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

    // Pure virtual functions for polymorphism
    virtual void investigate() const = 0;
    virtual void printResponseOptions() const = 0;
    virtual bool applyResponse(int actionChoice) = 0;
    virtual std::string getIncidentType() const = 0;
    virtual std::string getDetailedReport() const = 0;
};

/**
 * @class MalwareIncident
 * Derived class for malware, trojan, spyware, or ransomware events.
 */
class MalwareIncident : public SecurityIncident {
private:
    std::string m_category;
    std::string m_malwareSignature;
    std::string m_infectedProcess;
    bool m_isolatedFromNetwork;
    bool m_processTerminated;

public:
    MalwareIncident(int id, const std::string& title, IncidentSeverity severity,
                    NetworkDevice* targetDevice, const std::string& timestamp,
                    const std::string& category, const std::string& signature,
                    const std::string& infectedProcess);
    ~MalwareIncident() override = default;

    std::string getCategory() const;
    std::string getMalwareSignature() const;
    std::string getInfectedProcess() const;

    // Overridden virtual functions
    void investigate() const override;
    void printResponseOptions() const override;
    bool applyResponse(int actionChoice) override;
    std::string getIncidentType() const override;
    std::string getDetailedReport() const override;
};

/**
 * @class DDoSIncident
 * Derived class for Distributed Denial of Service flood attacks.
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

    // Overridden virtual functions
    void investigate() const override;
    void printResponseOptions() const override;
    bool applyResponse(int actionChoice) override;
    std::string getIncidentType() const override;
    std::string getDetailedReport() const override;
};

#endif // INCIDENT_H
