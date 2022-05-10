#include <fstream>
#include <assert.h>

int main(int argc, char const *argv[])
{
    std::ifstream f("f8cab909-04f5-497a-ac0f-402c62268360.png", std::ios::binary);
    assert(f.good());

    auto print_64 = [] (auto &f) {
        for (size_t i = 0; i < 64 && !f.eof(); i++)
            printf("%02X ", f.get());
        printf("\n");
    };
    print_64(f);
    f.seekg(-64, std::ios::end);
    print_64(f);
    return 0;
}
