#include "storage.h"

#include <sys/stat.h>

#include <fstream>
#include <stdexcept>

#include "crypto.h"
#include "json.h"

namespace {

json::Value entry_to_json(const Entry& e) {
    json::Value o = json::make_object();
    o["name"] = json::make_string(e.name);
    o["url"] = json::make_string(e.url);
    o["user"] = json::make_string(e.user);
    o["password"] = json::make_string(e.password);
    o["info"] = json::make_string(e.info);
    return o;
}

Entry entry_from_json(const json::Value& v) {
    Entry e;
    if (v.has("name")) e.name = v.at("name").as_string();
    if (v.has("url")) e.url = v.at("url").as_string();
    if (v.has("user")) e.user = v.at("user").as_string();
    if (v.has("password")) e.password = v.at("password").as_string();
    if (v.has("info")) e.info = v.at("info").as_string();
    return e;
}

json::Value vault_to_json(const Vault& v) {
    json::Value entries = json::make_array();
    for (const Entry& e : v.entries) {
        entries.array.push_back(entry_to_json(e));
    }
    json::Value o = json::make_object();
    o["entries"] = std::move(entries);
    return o;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open vault file: " + path);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return text;
}

std::string require_b64(const json::Value& v, const std::string& field) {
    if (!v.is_string()) throw std::runtime_error("vault is missing '" + field + "'");
    bool ok = false;
    std::string raw = crypto::base64_decode(v.as_string(), ok);
    if (!ok) throw std::runtime_error("invalid base64 in '" + field + "'");
    return raw;
}

}  // namespace

bool Vault::exists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good();
}

Vault Vault::load(const std::string& path, const std::string& master_password) {
    std::string text = read_file(path);
    if (text.empty()) throw std::runtime_error("vault file is empty");

    std::string err;
    json::Value w = json::parse(text, err);
    if (!err.empty() || w.is_null()) {
        throw std::runtime_error("vault file is not valid JSON: " + err);
    }

    const json::Value& kdf = w.at("kdf");
    unsigned int iterations = kIterations;
    if (kdf.is_object() && kdf.has("iterations")) {
        iterations = static_cast<unsigned int>(kdf.at("iterations").as_number());
    }
    std::string salt = require_b64(kdf.at("salt"), "kdf.salt");

    crypto::EncryptedBlob blob;
    blob.iv = require_b64(w.at("iv"), "iv");
    blob.tag = require_b64(w.at("tag"), "tag");
    blob.ciphertext = require_b64(w.at("data"), "data");

    std::string key = crypto::derive_key(master_password, salt, iterations);
    std::string plain;
    if (!crypto::decrypt(key, blob, plain)) {
        throw std::runtime_error("wrong master password or corrupted vault");
    }

    json::Value inner = json::parse(plain, err);
    if (!err.empty() || inner.is_null()) {
        throw std::runtime_error("decrypted data is not valid JSON: " + err);
    }

    Vault v;
    const json::Value& entries = inner.at("entries");
    if (entries.is_array()) {
        for (const json::Value& ev : entries.array) {
            if (ev.is_object()) v.entries.push_back(entry_from_json(ev));
        }
    }
    return v;
}

void Vault::save(const std::string& path, const std::string& master_password) const {
    std::string plain = json::dump(vault_to_json(*this));

    std::string salt(crypto::kSaltLen, '\0');
    crypto::random_bytes(reinterpret_cast<unsigned char*>(&salt[0]), salt.size());
    std::string key = crypto::derive_key(master_password, salt, kIterations);
    crypto::EncryptedBlob blob = crypto::encrypt(key, plain);

    json::Value w = json::make_object();
    w["version"] = json::make_number(1);
    w["cipher"] = json::make_string("aes-256-gcm");
    json::Value kdf = json::make_object();
    kdf["algo"] = json::make_string("pbkdf2-sha256");
    kdf["iterations"] = json::make_number(kIterations);
    kdf["salt"] = json::make_string(crypto::base64_encode(
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size()));
    w["kdf"] = std::move(kdf);
    w["iv"] = json::make_string(crypto::base64_encode(
        reinterpret_cast<const unsigned char*>(blob.iv.data()), blob.iv.size()));
    w["tag"] = json::make_string(crypto::base64_encode(
        reinterpret_cast<const unsigned char*>(blob.tag.data()), blob.tag.size()));
    w["data"] = json::make_string(crypto::base64_encode(
        reinterpret_cast<const unsigned char*>(blob.ciphertext.data()),
        blob.ciphertext.size()));

    std::string out = json::dump(w) + "\n";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot open vault file for writing: " + path);
    f.write(out.data(), static_cast<std::streamsize>(out.size()));
    f.close();
    if (!f) throw std::runtime_error("failed to write vault file");
    chmod(path.c_str(), 0600);
}

Entry* Vault::find(const std::string& name) {
    for (Entry& e : entries) {
        if (e.name == name) return &e;
    }
    return nullptr;
}
