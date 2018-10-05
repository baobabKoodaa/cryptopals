#include <iostream>
#include "set1.h"

int main() {
    try {
        std::cout << "Hello, World!" << std::endl;
        set1_prints();
    } catch (std::exception& e) {
        std::cout << "Exception! " << e.what() << std::endl;
    } catch (...) {
        std::cout << "Unknown exception!" << std::endl;
    }


    return 0;
}