#include "json.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace json {

Value null() { return Value{}; }
Value make_bool(bool b) { Value v; v.type = Value::Type::Boolean; v.boolean = b; return v; }
Value make_number(double n) { Value v; v.type = Value::Type::Number; v.number = n; return v; }
Value make_string(std::string s) { Value v; v.type = Value::Type::String; v.str = std::move(s); return v; }
Value make_array() { Value v; v.type = Value::Type::Array; return v; }
Value make_object() { Value v; v.type = Value::Type::Object; return v; }

const Value& Value::at(const std::string& key) const {
    static const Value missing;
    auto it = object.find(key);
    return it != object.end() ? it->second : missing;
}

namespace {

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string dump_impl(const Value& v) {
    switch (v.type) {
        case Value::Type::Null:
            return "null";
        case Value::Type::Boolean:
            return v.boolean ? "true" : "false";
        case Value::Type::Number: {
            if (std::isfinite(v.number) && std::floor(v.number) == v.number &&
                std::fabs(v.number) < 1e15) {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v.number));
                return buf;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", v.number);
            return buf;
        }
        case Value::Type::String:
            return "\"" + escape(v.str) + "\"";
        case Value::Type::Array: {
            std::string out = "[";
            for (size_t i = 0; i < v.array.size(); ++i) {
                if (i) out += ",";
                out += dump_impl(v.array[i]);
            }
            return out + "]";
        }
        case Value::Type::Object: {
            std::string out = "{";
            size_t i = 0;
            for (const auto& [k, val] : v.object) {
                if (i++) out += ",";
                out += "\"" + escape(k) + "\":" + dump_impl(val);
            }
            return out + "}";
        }
    }
    return "null";
}

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text) {}

    Value parse(std::string& error) {
        skip_ws();
        Value v = parse_value(error);
        if (!error.empty()) return null();
        skip_ws();
        if (pos_ != s_.size()) {
            error = "unexpected trailing characters";
            return null();
        }
        return v;
    }

private:
    const std::string& s_;
    size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }

    bool consume(char c) {
        if (pos_ < s_.size() && s_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    Value parse_value(std::string& error) {
        if (pos_ >= s_.size()) {
            error = "unexpected end of input";
            return null();
        }
        char c = s_[pos_];
        if (c == '{') return parse_object(error);
        if (c == '[') return parse_array(error);
        if (c == '"') return parse_string(error);
        if (c == 't') return parse_literal("true", make_bool(true), error);
        if (c == 'f') return parse_literal("false", make_bool(false), error);
        if (c == 'n') return parse_literal("null", null(), error);
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number(error);
        error = std::string("unexpected character '") + c + "'";
        return null();
    }

    Value parse_literal(const char* lit, Value val, std::string& error) {
        size_t n = std::strlen(lit);
        if (s_.compare(pos_, n, lit) == 0) {
            pos_ += n;
            return val;
        }
        error = "invalid literal";
        return null();
    }

    Value parse_string(std::string& error) {
        ++pos_;  // consume opening quote
        std::string out;
        while (pos_ < s_.size()) {
            unsigned char c = s_[pos_++];
            if (c == '"') return make_string(out);
            if (c == '\\') {
                if (pos_ >= s_.size()) break;
                char e = s_[pos_++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            if (pos_ >= s_.size()) { error = "invalid \\u escape"; return null(); }
                            int d = hexval(s_[pos_++]);
                            if (d < 0) { error = "invalid \\u escape"; return null(); }
                            cp = (cp << 4) | static_cast<unsigned>(d);
                        }
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (pos_ + 1 >= s_.size() || s_[pos_] != '\\' || s_[pos_ + 1] != 'u') {
                                error = "invalid surrogate pair";
                                return null();
                            }
                            pos_ += 2;
                            unsigned lo = 0;
                            for (int i = 0; i < 4; ++i) {
                                if (pos_ >= s_.size()) { error = "invalid \\u escape"; return null(); }
                                int d = hexval(s_[pos_++]);
                                if (d < 0) { error = "invalid \\u escape"; return null(); }
                                lo = (lo << 4) | static_cast<unsigned>(d);
                            }
                            if (lo < 0xDC00 || lo > 0xDFFF) {
                                error = "invalid surrogate pair";
                                return null();
                            }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            out += static_cast<char>(0xF0 | (cp >> 18));
                            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            if (cp <= 0x7F) {
                                out += static_cast<char>(cp);
                            } else if (cp <= 0x7FF) {
                                out += static_cast<char>(0xC0 | (cp >> 6));
                                out += static_cast<char>(0x80 | (cp & 0x3F));
                            } else {
                                out += static_cast<char>(0xE0 | (cp >> 12));
                                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                                out += static_cast<char>(0x80 | (cp & 0x3F));
                            }
                        }
                        break;
                    }
                    default:
                        error = "invalid escape sequence";
                        return null();
                }
            } else if (c < 0x20) {
                error = "unexpected control character in string";
                return null();
            } else {
                out += static_cast<char>(c);
            }
        }
        error = "unterminated string";
        return null();
    }

    Value parse_number(std::string& error) {
        size_t start = pos_;
        consume('-');
        while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        if (consume('.')) {
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        }
        std::string num = s_.substr(start, pos_ - start);
        char* end = nullptr;
        double d = std::strtod(num.c_str(), &end);
        if (end == num.c_str() || *end != '\0') {
            error = "invalid number";
            return null();
        }
        return make_number(d);
    }

    Value parse_array(std::string& error) {
        ++pos_;  // consume '['
        Value arr = make_array();
        skip_ws();
        if (consume(']')) return arr;
        while (true) {
            skip_ws();
            Value v = parse_value(error);
            if (!error.empty()) return null();
            arr.array.push_back(std::move(v));
            skip_ws();
            if (consume(',')) continue;
            if (consume(']')) return arr;
            error = "expected ',' or ']'";
            return null();
        }
    }

    Value parse_object(std::string& error) {
        ++pos_;  // consume '{'
        Value obj = make_object();
        skip_ws();
        if (consume('}')) return obj;
        while (true) {
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != '"') {
                error = "expected string key";
                return null();
            }
            Value key = parse_string(error);
            if (!error.empty()) return null();
            skip_ws();
            if (!consume(':')) {
                error = "expected ':'";
                return null();
            }
            skip_ws();
            Value val = parse_value(error);
            if (!error.empty()) return null();
            obj.object[key.str] = std::move(val);
            skip_ws();
            if (consume(',')) continue;
            if (consume('}')) return obj;
            error = "expected ',' or '}'";
            return null();
        }
    }
};

}  // namespace

std::string dump(const Value& v) { return dump_impl(v); }

Value parse(const std::string& text, std::string& error) {
    error.clear();
    Parser p(text);
    return p.parse(error);
}

}  // namespace json
