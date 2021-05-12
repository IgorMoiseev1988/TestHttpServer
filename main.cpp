#include "http_server.h"

#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    Http::Server server(8080);
    server.main_cycle();
    return 0;
}
