#ifndef SIMULATOR_H
#define SIMULATOR_H

#include "Device.h"
#include "Incident.h"
#include <vector>
#include <memory>
#include <string>

/**
 * @class SimulatorApp
 * @brief Central controller managing network topology, incident lifecycle, and user interactions.
 * Demonstrates: Ownership via std::unique_ptr, dynamic dispatch, and stream file handling.
 */
class SimulatorApp {
private:
    std::vector<std::unique_ptr<NetworkDevice>> m_devices;
    std::vector<std::unique_ptr<SecurityIncident>> m_incidents;
    int m_nextIncidentId;
    int m_nextDeviceId;

    // Helper methods
    void initializeDefaultNetwork();
    NetworkDevice* findDeviceById(int id) const;
    SecurityIncident* findIncidentById(int id) const;
    std::string getCurrentTimestamp() const;
    int getValidatedIntInput(int minVal, int maxVal) const;

public:
    SimulatorApp();
    ~SimulatorApp() = default;

    // Disable copy semantics to prevent unintended cloning of unique_ptr collections
    SimulatorApp(const SimulatorApp&) = delete;
    SimulatorApp& operator=(const SimulatorApp&) = delete;

    // Core operational loop
    void run();

    // Menu Action Handlers
    void viewNetworkStatus() const;
    void viewActiveIncidents() const;
    void investigateAndRespond();
    void generateRandomIncident();
    void saveIncidentReportToFile() const;
};

#endif // SIMULATOR_H
