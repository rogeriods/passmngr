#pragma once

#include <map>
#include <string>
#include <vector>

namespace json {

class Value {
public:
    enum class Type { Null, Boolean, Number, String, Array, Object };

    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;

    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    Array array;
    Object object;

    bool is_null() const { return type == Type::Null; }
    bool is_bool() const { return type == Type::Boolean; }
    bool is_number() const { return type == Type::Number; }
    bool is_string() const { return type == Type::String; }
    bool is_array() const { return type == Type::Array; }
    bool is_object() const { return type == Type::Object; }

    bool as_bool() const { return boolean; }
    double as_number() const { return number; }
    const std::string& as_string() const { return str; }

    bool has(const std::string& key) const { return object.count(key) != 0; }
    const Value& at(const std::string& key) const;
    Value& operator[](const std::string& key) { return object[key]; }
};

Value null();
Value make_bool(bool b);
Value make_number(double n);
Value make_string(std::string s);
Value make_array();
Value make_object();

std::string dump(const Value& value);
Value parse(const std::string& text, std::string& error);

}  // namespace json
