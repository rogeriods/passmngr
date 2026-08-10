#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "crypto.h"
#include "storage.h"

namespace {

const char* kAppName = "passmngr";
const std::string kVaultFile = ".pass.json";

void usage(std::ostream& os) {
    os << "Usage: " << kAppName << " <command> [args]\n"
       << "\n"
       << "Commands:\n"
       << "  init                      Create a new encrypted vault\n"
       << "  add NAME [--url URL] [--user USER] [--info TEXT] [--gen]\n"
       << "                            Add an entry (password prompted; --gen generates one)\n"
       << "  list                      List all entries\n"
       << "  show NAME [-p]            Show an entry (-p reveals the password)\n"
       << "  edit NAME                 Edit an entry (empty input keeps the current value)\n"
       << "  rm NAME                   Remove an entry\n"
       << "  pw                        Change the master password\n"
       << "  gen [LENGTH]              Generate a random password (default 20)\n"
       << "  help                      Show this help\n"
       << "\n"
       << "The vault is encrypted with AES-256-GCM (key from PBKDF2-SHA256) and\n"
       << "stored at ~/" << kVaultFile << "\n";
}

std::string vault_path() {
    const char* home = std::getenv("HOME");
    if (!home) {
        std::cerr << kAppName << ": HOME is not set\n";
        std::exit(1);
    }
    return std::string(home) + "/" + kVaultFile;
}

std::string prompt(const std::string& label) {
    std::cout << label;
    std::cout.flush();
    std::string line;
    std::getline(std::cin, line);
    return line;
}

std::string prompt_hidden(const std::string& label) {
    std::cout << label;
    std::cout.flush();
    termios oldt, newt;
    bool have_term = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (have_term) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    std::string line;
    std::getline(std::cin, line);
    if (have_term) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    return line;
}

bool confirm(const std::string& label) {
    std::string ans = prompt(label + " [y/N] ");
    return ans == "y" || ans == "Y" || ans == "yes" || ans == "YES";
}

std::string generate_password(size_t len) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "!@#$%^&*()-_=+[]{};:,.<>?";
    const size_t cs = sizeof(charset) - 1;
    if (len == 0) len = 20;
    std::string pwd(len, '\0');
    std::vector<unsigned char> buf(len);
    crypto::random_bytes(buf.data(), buf.size());
    for (size_t i = 0; i < len; ++i) pwd[i] = charset[buf[i] % cs];
    return pwd;
}

bool load_or_report(const std::string& path, const std::string& master, Vault& out) {
    try {
        out = Vault::load(path, master);
        return true;
    } catch (const std::exception& e) {
        std::cerr << kAppName << ": " << e.what() << "\n";
        return false;
    }
}

bool save_or_report(const std::string& path, const std::string& master, const Vault& v) {
    try {
        v.save(path, master);
        return true;
    } catch (const std::exception& e) {
        std::cerr << kAppName << ": " << e.what() << "\n";
        return false;
    }
}

int cmd_init(const std::string& path) {
    if (Vault::exists(path)) {
        std::cerr << kAppName << ": vault already exists at " << path << "\n";
        return 1;
    }
    std::string p1 = prompt_hidden("New master password: ");
    if (p1.size() < 8) {
        std::cerr << kAppName << ": master password must be at least 8 characters\n";
        return 1;
    }
    std::string p2 = prompt_hidden("Confirm master password: ");
    if (p1 != p2) {
        std::cerr << kAppName << ": passwords do not match\n";
        return 1;
    }
    Vault v;
    if (!save_or_report(path, p1, v)) return 1;
    std::cout << kAppName << ": vault created at " << path << "\n";
    return 0;
}

int cmd_add(const std::string& path, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        usage(std::cerr);
        return 1;
    }
    std::string name = args[1];
    std::string url, user, info;
    bool gen = false;
    for (size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--url" && i + 1 < args.size()) url = args[++i];
        else if (args[i] == "--user" && i + 1 < args.size()) user = args[++i];
        else if (args[i] == "--info" && i + 1 < args.size()) info = args[++i];
        else if (args[i] == "--gen") gen = true;
        else {
            std::cerr << kAppName << ": unknown argument '" << args[i] << "'\n";
            usage(std::cerr);
            return 1;
        }
    }

    std::string master = prompt_hidden("Master password: ");
    Vault v;
    if (!load_or_report(path, master, v)) return 1;
    if (v.find(name)) {
        std::cerr << kAppName << ": entry '" << name << "' already exists\n";
        return 1;
    }

    Entry e;
    e.name = name;
    if (url.empty()) url = prompt("URL [" + name + "]: ");
    e.url = url;
    if (user.empty()) user = prompt("User: ");
    e.user = user;
    if (gen) {
        e.password = generate_password(20);
        std::cout << "Generated password: " << e.password << "\n";
    } else {
        e.password = prompt_hidden("Password: ");
    }
    if (info.empty()) info = prompt("Info: ");
    e.info = info;

    v.entries.push_back(e);
    if (!save_or_report(path, master, v)) return 1;
    std::cout << kAppName << ": entry '" << name << "' added\n";
    return 0;
}

int cmd_list(const std::string& path) {
    std::string master = prompt_hidden("Master password: ");
    Vault v;
    if (!load_or_report(path, master, v)) return 1;
    if (v.entries.empty()) {
        std::cout << kAppName << ": no entries\n";
        return 0;
    }
    std::cout << std::left << std::setw(5) << "#" << std::setw(24) << "NAME"
              << std::setw(28) << "USER" << "URL\n";
    for (size_t i = 0; i < v.entries.size(); ++i) {
        const Entry& e = v.entries[i];
        std::cout << std::left << std::setw(5) << (i + 1) << std::setw(24) << e.name
                  << std::setw(28) << e.user << e.url << "\n";
    }
    return 0;
}

int cmd_show(const std::string& path, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        usage(std::cerr);
        return 1;
    }
    std::string name = args[1];
    bool reveal = false;
    for (size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "-p") reveal = true;
        else {
            std::cerr << kAppName << ": unknown argument '" << args[i] << "'\n";
            return 1;
        }
    }
    std::string master = prompt_hidden("Master password: ");
    Vault v;
    if (!load_or_report(path, master, v)) return 1;
    const Entry* e = v.find(name);
    if (!e) {
        std::cerr << kAppName << ": entry '" << name << "' not found\n";
        return 1;
    }
    std::cout << "Name:     " << e->name << "\n"
              << "URL:      " << (e->url.empty() ? "-" : e->url) << "\n"
              << "User:     " << (e->user.empty() ? "-" : e->user) << "\n"
              << "Password: " << (reveal ? e->password : "******** (use -p to reveal)") << "\n"
              << "Info:     " << (e->info.empty() ? "-" : e->info) << "\n";
    return 0;
}

int cmd_edit(const std::string& path, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        usage(std::cerr);
        return 1;
    }
    std::string name = args[1];
    std::string master = prompt_hidden("Master password: ");
    Vault v;
    if (!load_or_report(path, master, v)) return 1;
    Entry* e = v.find(name);
    if (!e) {
        std::cerr << kAppName << ": entry '" << name << "' not found\n";
        return 1;
    }
    std::cout << "Leave empty to keep the current value.\n";
    std::string url = prompt("URL [" + e->url + "]: ");
    if (!url.empty()) e->url = url;
    std::string user = prompt("User [" + e->user + "]: ");
    if (!user.empty()) e->user = user;
    std::string pwd = prompt_hidden("Password (empty keeps current): ");
    if (!pwd.empty()) e->password = pwd;
    std::string info = prompt("Info [" + e->info + "]: ");
    if (!info.empty()) e->info = info;
    if (!save_or_report(path, master, v)) return 1;
    std::cout << kAppName << ": entry '" << name << "' updated\n";
    return 0;
}

int cmd_rm(const std::string& path, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        usage(std::cerr);
        return 1;
    }
    std::string name = args[1];
    std::string master = prompt_hidden("Master password: ");
    Vault v;
    if (!load_or_report(path, master, v)) return 1;
    size_t idx = v.entries.size();
    for (size_t i = 0; i < v.entries.size(); ++i) {
        if (v.entries[i].name == name) {
            idx = i;
            break;
        }
    }
    if (idx == v.entries.size()) {
        std::cerr << kAppName << ": entry '" << name << "' not found\n";
        return 1;
    }
    if (!confirm("Remove entry '" + name + "'?")) {
        std::cout << kAppName << ": aborted\n";
        return 0;
    }
    v.entries.erase(v.entries.begin() + static_cast<long>(idx));
    if (!save_or_report(path, master, v)) return 1;
    std::cout << kAppName << ": entry '" << name << "' removed\n";
    return 0;
}

int cmd_pw(const std::string& path) {
    std::string oldm = prompt_hidden("Current master password: ");
    Vault v;
    if (!load_or_report(path, oldm, v)) return 1;
    std::string p1 = prompt_hidden("New master password: ");
    if (p1.size() < 8) {
        std::cerr << kAppName << ": master password must be at least 8 characters\n";
        return 1;
    }
    std::string p2 = prompt_hidden("Confirm new master password: ");
    if (p1 != p2) {
        std::cerr << kAppName << ": passwords do not match\n";
        return 1;
    }
    if (!save_or_report(path, p1, v)) return 1;
    std::cout << kAppName << ": master password changed\n";
    return 0;
}

int cmd_gen(const std::vector<std::string>& args) {
    size_t len = 20;
    if (args.size() >= 2) {
        char* end = nullptr;
        long l = std::strtol(args[1].c_str(), &end, 10);
        if (end == args[1].c_str() || *end != '\0' || l <= 0 || l > 1024) {
            std::cerr << kAppName << ": invalid length '" << args[1] << "' (1-1024)\n";
            return 1;
        }
        len = static_cast<size_t>(l);
    }
    std::cout << generate_password(len) << "\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        usage(std::cout);
        return 0;
    }
    const std::string& cmd = args[0];

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        usage(std::cout);
        return 0;
    }
    if (cmd == "gen") return cmd_gen(args);

    const std::string path = vault_path();

    if (cmd == "init") return cmd_init(path);
    if (cmd == "add") return cmd_add(path, args);
    if (cmd == "list") return cmd_list(path);
    if (cmd == "show") return cmd_show(path, args);
    if (cmd == "edit") return cmd_edit(path, args);
    if (cmd == "rm" || cmd == "remove") return cmd_rm(path, args);
    if (cmd == "pw") return cmd_pw(path);

    std::cerr << kAppName << ": unknown command '" << cmd << "'\n";
    usage(std::cerr);
    return 1;
}
