#include <iostream>
#include <cstring>

int main() {
    char buffer[8];
    const char *data = "This string is definitely longer than 8 bytes";
    strcpy(buffer, data);
    std::cout << buffer << std::endl;
    return 0;
}