#include "../include/Simulator.h"
#include <iostream>
#include <exception>

int main() {
    try {
        SimulatorApp app;
        app.run();
    } catch (const std::exception& ex) {
        std::cerr << "\n[CRITICAL ERROR] Unhandled exception occurred: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n[CRITICAL ERROR] Unknown exception occurred during simulation execution." << std::endl;
        return 2;
    }
    return 0;
}
