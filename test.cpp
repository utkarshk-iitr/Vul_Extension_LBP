#include <iostream>
#include <cstring>
#include <string>

void vulnerableFunction(const char* userInput) {
    char smallBuffer[10]; // Can hold 9 characters + null terminator
    
    // Unsafe: No bounds checking on userInput length!
    strncpy(smallBuffer, userInput, sizeof(smallBuffer) - 1); smallBuffer[sizeof(smallBuffer) - 1] = '\0';
    
    std::cout << "Buffer content: " << smallBuffer << std::endl;
}

int main() {
    vulnerableFunction("ThisStringIsWayTooLong"); // Causes buffer overflow
    return 0;
}
