#pragma once

#include <string>
#include <vector>

struct Entry {
    std::string name;
    std::string url;
    std::string user;
    std::string password;
    std::string info;
};

class Vault {
public:
    static constexpr unsigned int kIterations = 600000;

    std::vector<Entry> entries;

    static bool exists(const std::string& path);
    static Vault load(const std::string& path, const std::string& master_password);
    void save(const std::string& path, const std::string& master_password) const;

    Entry* find(const std::string& name);
};
