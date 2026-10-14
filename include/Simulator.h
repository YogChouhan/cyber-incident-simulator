#ifndef SIMULATOR_H
#define SIMULATOR_H

#include "Device.h"
#include "Incident.h"
#include <vector>
#include <memory>
#include <string>

/**
 * @class SimulatorApp
 * Central manager class that controls network devices, active incidents, and simulation flow.
 */
class SimulatorApp {
private:
    std::vector<std::unique_ptr<NetworkDevice>> m_devices;
    std::vector<std::unique_ptr<SecurityIncident>> m_incidents;
    int m_nextIncidentId;
    int m_nextDeviceId;

    // Helper functions
    void initializeDefaultNetwork();
    NetworkDevice* findDeviceById(int id) const;
    SecurityIncident* findIncidentById(int id) const;
    std::string getCurrentTimestamp() const;
    int getValidatedIntInput(int minVal, int maxVal, const std::string& prompt = "") const;

public:
    SimulatorApp();
    ~SimulatorApp() = default;

    // Prevent accidental copying of unique_ptr collections
    SimulatorApp(const SimulatorApp&) = delete;
    SimulatorApp& operator=(const SimulatorApp&) = delete;

    // Main execution loop
    void run();

    // Menu handlers
    void viewNetworkStatus() const;
    void viewAllIncidents() const;
    void investigateAndRespond();
    void generateRandomIncident();
    void saveIncidentReportToFile() const;
};

#endif // SIMULATOR_H
