#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <iostream>

#include "sock_utils.h"

using json = nlohmann::json;

using namespace std;
int main() {
    // Example usage
    json example = {{"name", "John"}, {"age", 30}};
    std::cout << example["name"] << std::endl;
    std::cout << example.dump(4) << std::endl;
    uint32_t a = 30;
    cout << a << endl;
    ntohl(a);

    cout << a << endl;

    return 0;
}

