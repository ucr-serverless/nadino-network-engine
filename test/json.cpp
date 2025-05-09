#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

using namespace std;
static nlohmann::json read_json_from_file(const std::string& path) {

    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Could not open file at path: " + path);
    }

    try {
        json jsonData;
        file >> jsonData;
        return jsonData;
    } catch (const std::exception& e) {
        throw std::runtime_error("Error parsing JSON file: " + std::string(e.what()));
    }
}
int main() {
    // Example usage
    // json example = {{"name", "John"}, {"age", 30}};
    // std::cout << example["name"] << std::endl;
    // std::cout << example.dump(4) << std::endl;
    // uint32_t a = 30;
    // cout << a << endl;
    // ntohl(a);
    //
    // cout << a << endl;
    string path = "cfg/multi-tenancy-expt.json";
    json data = read_json_from_file(path);
    std::cout << data.dump(4);

    return 0;
}

