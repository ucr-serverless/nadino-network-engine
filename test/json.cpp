#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

int main() {
    // Example usage
    json example = {{"name", "John"}, {"age", 30}};
    std::cout << example.dump(4) << std::endl;
    return 0;
}

