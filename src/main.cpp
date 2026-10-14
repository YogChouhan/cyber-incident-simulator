#include "Simulator.h"
#include <iostream>
#include <exception>

using namespace std;

// Application entry point: initializes simulator and manages top-level exception handling
int main() {
    try {
        SimulatorApp app;
        app.run();
    } catch (const exception& ex) {
        cerr << "\n[APPLICATION FINISHED] " << ex.what() << endl;
        return 0;
    } catch (...) {
        cerr << "\n[CRITICAL ERROR] Unknown exception occurred during simulation execution." << endl;
        return 1;
    }
    return 0;
}
