#include <iostream>
#include <MemoryToolsCPP.hpp>

int main() {
    int aalll
    int val = 0;
    MemoryTools::Addr val_addr(&val);

    std::cout << static_cast<uintptr_t>(val_addr) << std::endl;

    std::cout << val << std::endl;

    val_addr.writeType<decltype(val)>(999);

    std::cout << val << std::endl;

    return 0;
}