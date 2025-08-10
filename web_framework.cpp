#ifdef _WIN32
#define _WIN32_WINNT 0x0601
#define ASIO_HAS_THREADS
#define ASIO_HAS_CHRONO
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/co_spawn.hpp>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <print>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>
#include <mutex>
#include <atomic>
#include <variant>
#include <charconv>
#include <format>
#include <iterator>

#ifdef DELETE
#undef DELETE
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace asio::experimental::awaitable_operators;

struct App;
struct Connection;
struct HttpRequest;
struct HttpResponse;
class SSEStream;
class Response;
struct RequestContext;

asio::awaitable<void> handle_request(App &app, std::shared_ptr<Connection> conn);
asio::awaitable<void> send_response(std::shared_ptr<Connection> conn, const HttpResponse &res);
asio::awaitable<void> serve_static_file(std::shared_ptr<Connection> conn, std::string path);
asio::awaitable<void> send_sse_headers(std::shared_ptr<Connection> conn);
asio::awaitable<void> start_disconnection_detection(App &app, std::shared_ptr<Connection> conn);
asio::awaitable<SSEStream*> setup_sse(App& app, std::shared_ptr<Connection> conn, const std::string& stream_name);
asio::awaitable<Response> chat_upload_handler(const RequestContext& ctx);


// URL encoding/decoding functions
std::string url_decode(std::string_view str) {
    std::string decoded_string;
    decoded_string.reserve(str.size());
    std::back_insert_iterator<std::string> out = std::back_inserter(decoded_string); 

    for (size_t i = 0; i < str.length(); ++i) {
        char c = str.at(i); 

        if (c == '%') {
            if (i + 2 < str.length()) { 
                unsigned char hex_value = 0;
                std::from_chars_result res = std::from_chars(str.data() + i + 1, str.data() + i + 3, hex_value, 16);

                if (res.ec == std::errc{} && res.ptr == str.data() + i + 3) {
                    std::format_to(out, "{}", static_cast<char>(hex_value));
                    i += 2;
                } else {
                    std::format_to(out, "{}", c); // Invalid hex sequence
                }
            } else {
                std::format_to(out, "{}", c); // Not enough characters after %
            }
        } else {
            std::format_to(out, "{}", c); // Regular character
        }
    }

    return decoded_string;
}

std::string url_encode(std::string_view str) {
    std::string result;
    result.reserve(str.size() * 3); 

    std::back_insert_iterator<std::string> out = std::back_inserter(result); 
    for (const char c : str) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            std::format_to(out, "{}", static_cast<char>(c));
        } else {
            std::format_to(out, "%{:02X}", static_cast<unsigned int>(c)); 
        }
    }

    return result;
}

// MIME type mapping
const std::unordered_map<std::string_view, std::string> MIME_TYPES = {
    {".html", "text/html"},        {".css", "text/css"},   {".js", "application/javascript"},
    {".json", "application/json"}, {".png", "image/png"},  {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},       {".gif", "image/gif"},  {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},      {".txt", "text/plain"}, {".woff", "font/woff"},
    {".woff2", "font/woff2"}};

// HTTP Method enum
enum class HttpMethod : std::uint8_t { GET, POST, PUT, DELETE, PATCH, OPTIONS };

std::string to_string(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: 
            return "GET";
        case HttpMethod::POST: 
            return "POST";
        case HttpMethod::PUT: 
            return "PUT";
        case HttpMethod::DELETE: 
            return "DELETE";
        case HttpMethod::PATCH: 
            return "PATCH";
        case HttpMethod::OPTIONS: 
            return "OPTIONS";
        default: 
            return {};
    }
}

// A type-safe container for a parsed route parameter
using RouteParamVariant = std::variant<
    std::string, 
    bool,
    int32_t, uint32_t, int64_t, uint64_t,
    float, double
>;

struct MultipartFile {
    std::string name;           // Form field name
    std::string filename;       // Original filename
    std::string content_type;   // MIME type
    std::vector<uint8_t> data;  // File content
    
    [[nodiscard]] size_t size() const { return data.size(); }
    [[nodiscard]] bool empty() const { return data.empty(); }
    
    // Save file to disk
    [[nodiscard]] bool save_to(const std::string& path) const {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        return file.good();
    }
    
    // Get content as string (useful for text files)
    [[nodiscard]] std::string as_string() const {
         return {data.begin(), data.end()};
    }
};

struct MultipartField {
    std::string name;
    std::string value;
    std::unordered_map<std::string, std::string> headers;
};

class MultipartParser {
public:
    struct ParseResult {
        std::vector<MultipartField> fields;
        std::vector<MultipartFile> files;
        std::string error;
        
        [[nodiscard]] bool success() const { return error.empty(); }
        
        // Get field value by name
        [[nodiscard]] std::string get_field(const std::string& name) const {
            for (const auto& field : fields) {
                if (field.name == name) return field.value;
            }
            return "";
        }
        
        // Get file by field name
        [[nodiscard]] const MultipartFile* get_file(const std::string& name) const {
            for (const auto& file : files) {
                if (file.name == name) return &file;
            }
            return nullptr;
        }
        
        // Check if field exists
        [[nodiscard]] bool has_field(const std::string& name) const {
            return std::any_of(fields.begin(), fields.end(), 
                [&name](const MultipartField& f) { return f.name == name; });
        }
        
        // Check if file exists
        [[nodiscard]] bool has_file(const std::string& name) const {
            return std::any_of(files.begin(), files.end(), 
                [&name](const MultipartFile& f) { return f.name == name; });
        }
    };

    static ParseResult parse(const std::string& body, const std::string& boundary) {
        ParseResult result;
        if (body.empty() || boundary.empty()) {
            result.error = "Empty body or boundary";
            return result;
        }

        std::string delimiter = "--" + boundary;
        std::string end_delimiter = delimiter + "--";
        size_t current_pos = 0;

        // Loop through each part, separated by the delimiter
        while (current_pos < body.length()) {
            size_t next_delimiter_pos = body.find(delimiter, current_pos);

            // If we can't find the next delimiter, we're done.
            if (next_delimiter_pos == std::string::npos) {
                break;
            }

            // If we're at the very start, skip over the first boundary.
            if (next_delimiter_pos == 0) {
                current_pos = delimiter.length();
                continue;
            }

            // Extract the full content of a single part (between two boundaries)
            std::string part = body.substr(current_pos, next_delimiter_pos - current_pos);

            // Each part should start with \r\n, trim it.
            if (part.rfind("\r\n", 0) == 0) {
                part = part.substr(2);
            }

            // Find the end of the headers (\r\n\r\n)
            size_t headers_end = part.find("\r\n\r\n");
            if (headers_end == std::string::npos) {
                current_pos = next_delimiter_pos + delimiter.length();
                continue; // Malformed or empty part, skip.
            }

            std::string headers_section = part.substr(0, headers_end);
            
            // --- This is the SAFE way to extract content ---
            std::string content = part.substr(headers_end + 4);
            // And safely remove the trailing \r\n
            if (content.length() >= 2 && content.substr(content.length() - 2) == "\r\n") {
                content.resize(content.length() - 2);
            }
            // --- End safe extraction ---

            // Header parsing logic...
            std::unordered_map<std::string, std::string> headers;
            std::string content_disposition;
            std::istringstream headers_stream(headers_section);
            std::string header_line;

            while (std::getline(headers_stream, header_line) && !header_line.empty()) {
                if (!header_line.empty() && header_line.back() == '\r') {
                    header_line.pop_back();
                }
                size_t colon_pos = header_line.find(": ");
                if (colon_pos != std::string::npos) {
                    std::string key = header_line.substr(0, colon_pos);
                    std::string value = header_line.substr(colon_pos + 2);
                    std::string lower_key = key;
                    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
                    headers[lower_key] = value;
                    if (lower_key == "content-disposition") content_disposition = value;
                }
            }
            
            if (content_disposition.empty()) {
                 current_pos = next_delimiter_pos + delimiter.length();
                 continue;
            }
            
            // Content-Disposition parsing...
            auto get_param = [](const std::string& cd_header, const std::string& param_name) -> std::string {
                size_t pos = cd_header.find(param_name + "=\"");
                if (pos == std::string::npos) return "";
                pos += param_name.length() + 2;
                size_t end_quote = cd_header.find('"', pos);
                if (end_quote == std::string::npos) return "";
                return cd_header.substr(pos, end_quote - pos);
            };

            std::string field_name = get_param(content_disposition, "name");
            std::string filename = get_param(content_disposition, "filename");

            if (field_name.empty()) {
                current_pos = next_delimiter_pos + delimiter.length();
                continue;
            }

            // Store the final parsed part
            if (!filename.empty()) {
                MultipartFile file;
                file.name = field_name;
                file.filename = filename;
                file.content_type = headers.count("content-type") ? headers.at("content-type") : "application/octet-stream";
                file.data.assign(content.begin(), content.end());
                result.files.push_back(std::move(file));
            } else {
                MultipartField field;
                field.name = field_name;
                field.value = content;
                field.headers = headers;
                result.fields.push_back(std::move(field));
            }

            current_pos = next_delimiter_pos + delimiter.length();
        }

        return result;
    }


private:
    static std::string trim(const std::string& str) {
        if (str.empty()) return "";
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }
};


// HTTP Request structure
struct HttpRequest {
    HttpMethod method{HttpMethod::GET};
    std::string path;
    std::string full_path;
    std::unordered_map<std::string, std::string> query_params;
    std::string_view protocol;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::unordered_map<std::string, RouteParamVariant> params;

    template<typename T = std::string>
    [[nodiscard]] std::pair<T, std::string> param(const std::string& key) const {
        auto it = params.find(key);
        if (it == params.end()) {
            return {T{}, "Parameter '" + key + "' not found"};
        }
        
        // Use std::get_if to safely get the value if the type T matches
        if (const T* value = std::get_if<T>(&it->second)) {
            return {*value, ""};  // Success: return value with empty error
        }
        
        return {T{}, "Parameter '" + key + "' has wrong type"};
    }

    static HttpRequest parse_headers(asio::streambuf &buffer) {
        HttpRequest req;
        std::istream is(&buffer);
        std::string line;

        try {
            std::getline(is, line);
            std::istringstream iss(line);
            std::string method_str, path_str, protocol;
            iss >> method_str >> path_str >> protocol;
            req.full_path = path_str;

            static const std::unordered_map<std::string_view, HttpMethod> method_map = {
                {"GET", HttpMethod::GET}, {"POST", HttpMethod::POST}, {"PUT", HttpMethod::PUT}, 
                {"DELETE", HttpMethod::DELETE}, {"PATCH", HttpMethod::PATCH}, {"OPTIONS", HttpMethod::OPTIONS}
            };

            req.method = method_map.contains(method_str) ? method_map.at(method_str) : HttpMethod::GET;
            
            size_t query_pos = path_str.find('?');
            if (query_pos != std::string::npos) {
                req.path = path_str.substr(0, query_pos);
                std::string query_string = path_str.substr(query_pos + 1);
                std::istringstream q_stream(query_string);
                std::string pair;
                while (std::getline(q_stream, pair, '&')) {
                    size_t eq_pos = pair.find('=');
                    if (eq_pos != std::string::npos) {
                        req.query_params[url_decode(pair.substr(0, eq_pos))] = url_decode(pair.substr(eq_pos + 1));
                    }
                }
            } else {
                req.path = path_str;
            }

            req.protocol = protocol;

            while (std::getline(is, line) && line != "\r") {
                line.erase(line.find_last_not_of("\r\n") + 1);
                if (!line.empty()) {
                    if (uint64_t colon = line.find(": "); colon != std::string::npos) {
                        req.headers[line.substr(0, colon)] = line.substr(colon + 2);
                    }
                }
            }
        } catch (const std::exception &e) {
            std::println("Error parsing request: {}", e.what());
        }
        
        return req;
    }

    [[nodiscard]] MultipartParser::ParseResult parse_multipart() const {
        auto content_type_it = headers.find("Content-Type");
        if (content_type_it == headers.end()) {
            MultipartParser::ParseResult result;
            result.error = "Missing Content-Type header";
            return result;
        }
        
        std::string content_type = content_type_it->second;
        
        // Check if it's multipart/form-data
        if (content_type.find("multipart/form-data") == std::string::npos) {
            MultipartParser::ParseResult result;
            result.error = "Not a multipart/form-data request";
            return result;
        }
        
        // Extract boundary
        size_t boundary_pos = content_type.find("boundary=");
        if (boundary_pos == std::string::npos) {
            MultipartParser::ParseResult result;
            result.error = "Missing boundary in Content-Type";
            return result;
        }
        
        std::string boundary = content_type.substr(boundary_pos + 9);
        
        // Remove quotes if present and trim whitespace
        if (!boundary.empty() && boundary.front() == '"' && boundary.back() == '"') {
            boundary = boundary.substr(1, boundary.length() - 2);
        }
        
        // Remove any trailing semicolons or whitespace
        size_t semicolon_pos = boundary.find(';');
        if (semicolon_pos != std::string::npos) {
            boundary = boundary.substr(0, semicolon_pos);
        }
        
        // Trim whitespace
        boundary.erase(0, boundary.find_first_not_of(" \t"));
        boundary.erase(boundary.find_last_not_of(" \t") + 1);
        
        if (boundary.empty()) {
            MultipartParser::ParseResult result;
            result.error = "Empty boundary in Content-Type";
            return result;
        }
        
        return MultipartParser::parse(body, boundary);
    }

    [[nodiscard]] bool is_multipart() const {
        auto it = headers.find("Content-Type");
        return it != headers.end() && it->second.find("multipart/form-data") != std::string::npos;
    }

};

// HTTP Response structure
struct HttpResponse {
    std::string status;
    std::unordered_map<std::string_view, std::string> headers;
    std::string body;

    [[nodiscard]] std::string to_string() const {
        std::string res = std::format("HTTP/1.1 {}\r\n", status);
        std::back_insert_iterator<std::string> resp = std::back_inserter(res);

        for (const auto& [key, value] : headers) {
            std::format_to(resp, "{}: {}\r\n", key, value);
        }

        std::format_to(resp, "Content-Length: {}\r\n\r\n{}", body.size(), body);
        return res;
    }
    
};

class Response {
private:
    HttpResponse response_;
    bool should_send_response_ = true;
    static std::string sanitize_content_disposition_filename(const std::string& filename) {
       std::string sanitized = filename;
        
        // Replace quotes and backslashes which can break the header
        for (char& c : sanitized) {
            if (c == '"' || c == '\\' || c == '\r' || c == '\n') {
                c = '_';
            }
        }
        
        // Limit length to prevent header issues
        if (sanitized.length() > 200) {
            sanitized.resize(200);
        }
        
        return sanitized;
    }

public:
    Response() {
        response_.status = "200 OK";
        response_.headers["Connection"] = "close";
    }
    
    explicit Response(const char* text) : Response() {
        response_.headers["Content-Type"] = "text/plain";
        response_.body = text;
    }

    explicit Response(const std::string& text) : Response() {
        response_.headers["Content-Type"] = "text/plain";
        response_.body = text;
    }

    explicit Response(const json& data) : Response() {
        response_.headers["Content-Type"] = "application/json";
        response_.body = data.dump();
    }
    
    explicit Response(int32_t status_code) {
        response_.headers["Connection"] = "close";
        switch (status_code) {
            case 200: response_.status = "200 OK"; 
                break;
            case 201: response_.status = "201 Created"; 
                break;
            case 400: response_.status = "400 Bad Request"; 
                break;
            case 401: response_.status = "401 Unauthorized"; 
                break;
            case 403: response_.status = "403 Forbidden"; 
                break;
            case 404: response_.status = "404 Not Found"; 
                break;
            case 409: response_.status = "409 Conflict"; 
                break;
            case 500: response_.status = "500 Internal Server Error"; 
                break;
            default: response_.status = std::to_string(status_code) + " Unknown"; 
                break;
        }
    }
    
    // Chain methods for error responses
    Response& json(const nlohmann::json& data) {
        response_.headers["Content-Type"] = "application/json";
        response_.body = data.dump();
        return *this;
    }
    
    Response& text(std::string_view content) {
        response_.headers["Content-Type"] = "text/plain";
        response_.body = content;
        return *this;
    }
    
    Response& html(std::string_view content) {
        response_.headers["Content-Type"] = "text/html";
        response_.body = content;
        return *this;
    }
    
    // Header methods
    Response& header(std::string_view key, std::string_view value) {
        response_.headers[key] = value;
        return *this;
    }
    
    Response& cors() {
        response_.headers["Access-Control-Allow-Origin"] = "*";
        response_.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        response_.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        return *this;
    }
    
    static Response no_response() {
        Response resp;
        resp.should_send_response_ = false;
        return resp;
    }
    
    [[nodiscard]] bool should_send() const { return should_send_response_; }

    // Conversion to HttpResponse
    operator HttpResponse() const { 
        return response_; 
    }

    [[nodiscard]] HttpResponse build() const { return response_; }

        // File download methods
    Response& download_file(const std::string& file_path, const std::string& download_name = "") {
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            response_.status = "404 Not Found";
            response_.body = "File not found";
            return *this;
        }
        
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            response_.status = "500 Internal Server Error";
            response_.body = "Unable to read file";
            return *this;
        }
        
        // Read file content
        response_.body = std::string((std::istreambuf_iterator<char>(file)), 
                                   std::istreambuf_iterator<char>());
        
        // Set content type based on file extension
        std::string ext = fs::path(file_path).extension().string();
        std::string content_type = MIME_TYPES.contains(ext) ? 
                                  MIME_TYPES.at(ext) : "application/octet-stream";
        response_.headers["Content-Type"] = content_type;
        
        // Set Content-Disposition header for download
        std::string filename = download_name.empty() ? 
                              fs::path(file_path).filename().string() : download_name;
        response_.headers["Content-Disposition"] = 
            std::format("attachment; filename=\"{}\"", sanitize_content_disposition_filename(filename));
        
        // Set other useful headers
        response_.headers["Content-Length"] = std::to_string(response_.body.size());
        response_.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        
        return *this;
    }
    
    // Serve file inline (display in browser)
    Response& serve_file(const std::string& file_path, const std::string& display_name = "") {
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            response_.status = "404 Not Found";
            response_.body = "File not found";
            return *this;
        }
        
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            response_.status = "500 Internal Server Error";
            response_.body = "Unable to read file";
            return *this;
        }
        
        // Read file content
        response_.body = std::string((std::istreambuf_iterator<char>(file)), 
                                   std::istreambuf_iterator<char>());
        
        // Set content type
        std::string ext = fs::path(file_path).extension().string();
        std::string content_type = MIME_TYPES.contains(ext) ? 
                                  MIME_TYPES.at(ext) : "application/octet-stream";
        response_.headers["Content-Type"] = content_type;
        
        // Set Content-Disposition for inline display
        if (!display_name.empty()) {
            response_.headers["Content-Disposition"] = 
                std::format("inline; filename=\"{}\"", sanitize_content_disposition_filename(display_name));
        }
        
        response_.headers["Content-Length"] = std::to_string(response_.body.size());
        
        return *this;
    }
    
    // Stream binary data as download
    Response& download_data(const std::vector<uint8_t>& data, const std::string& filename, 
                           const std::string& content_type = "application/octet-stream") {
        response_.body.assign(data.begin(), data.end());
        response_.headers["Content-Type"] = content_type;
        response_.headers["Content-Disposition"] = 
            std::format("attachment; filename=\"{}\"", sanitize_content_disposition_filename(filename));
        response_.headers["Content-Length"] = std::to_string(data.size());
        response_.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        
        return *this;
    }
    
    // Stream text data as download
    Response& download_text(const std::string& text_data, const std::string& filename, 
                           const std::string& content_type = "text/plain") {
        response_.body = text_data;
        response_.headers["Content-Type"] = content_type;
        response_.headers["Content-Disposition"] = 
            std::format("attachment; filename=\"{}\"", sanitize_content_disposition_filename(filename));
        response_.headers["Content-Length"] = std::to_string(text_data.size());
        response_.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        
        return *this;
    }
    
    // Set custom Content-Disposition header
    Response& content_disposition(const std::string& disposition_type, const std::string& filename = "") {
        if (filename.empty()) {
            response_.headers["Content-Disposition"] = disposition_type;
        } else {
            response_.headers["Content-Disposition"] = 
                std::format("{}; filename=\"{}\"", disposition_type, 
                           sanitize_content_disposition_filename(filename));
        }
        return *this;
    }

};

// Global helper functions for common patterns
Response success(const std::string& text) {
    return Response(text); 
}

Response success(const char* text) {
    return Response(text); 
}

Response success(const json& data) {
    return Response(data); 
}

Response created(const json& data) { 
    Response resp(201);
    return resp.json(data);
}

Response bad_request(std::string_view message) { 
    Response resp(400);
    return resp.text(message);
}

Response not_found(std::string_view message = "Not Found") { 
    Response resp(404);
    return resp.text(message);
}

Response error(int32_t code) { 
    return Response(code); 
}

Response failure(std::string_view message, int32_t code = 400) {
    json result;
    result["error"] = message;
    Response resp(code);

    return resp.json(result);
}

Response download_file(const std::string& file_path, const std::string& download_name = "") {
    Response resp;
    return resp.download_file(file_path, download_name);
}

Response serve_file(const std::string& file_path, const std::string& display_name = "") {
    Response resp;
    return resp.serve_file(file_path, display_name);
}

Response download_data(const std::vector<uint8_t>& data, const std::string& filename, 
                      const std::string& content_type = "application/octet-stream") {
    Response resp;
    return resp.download_data(data, filename, content_type);
}

Response download_text(const std::string& text_data, const std::string& filename, 
                      const std::string& content_type = "text/plain") {
    Response resp;
    return resp.download_text(text_data, filename, content_type);
}

class QueryParams {
private:
    const std::unordered_map<std::string, std::string>& params_;
    
public:
    explicit QueryParams(const std::unordered_map<std::string, std::string>& params) : params_(params) {}
    
    template<typename T = std::string>
    [[nodiscard]] std::pair<T, std::string> get(const std::string& key) const {
        auto it = params_.find(key);
        if (it == params_.end() || it->second.empty()) {
            return {T{}, "Query parameter '" + key + "' not found or empty"};
        }
        
        const std::string& value = it->second;
        
        try {
            if constexpr (std::is_same_v<T, std::string>) {
                return {value, ""};
            } else if constexpr (std::is_same_v<T, bool>) {
                std::string lower_val = value;
                std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(), ::tolower);
                if (lower_val == "true" || lower_val == "1" || lower_val == "yes") {
                    return {true, ""};
                } else if (lower_val == "false" || lower_val == "0" || lower_val == "no") {
                    return {false, ""};
                }
                return {T{}, "Invalid boolean value: " + value};
            } else if constexpr (std::is_same_v<T, int32_t>) {
                long long temp_val = std::stoll(value);
                if (temp_val < std::numeric_limits<int32_t>::min() || temp_val > std::numeric_limits<int32_t>::max()) {
                    return {T{}, "Value out of range for int32_t: " + value};
                }
                return {static_cast<int32_t>(temp_val), ""};
            } else if constexpr (std::is_same_v<T, uint32_t>) {
                if (value.empty() || value[0] == '-') {
                    return {T{}, "Negative value for uint32_t: " + value};
                }
                unsigned long long temp_val = std::stoull(value);
                if (temp_val > std::numeric_limits<uint32_t>::max()) {
                    return {T{}, "Value out of range for uint32_t: " + value};
                }
                return {static_cast<uint32_t>(temp_val), ""};
            } else if constexpr (std::is_same_v<T, int64_t>) {
                return {std::stoll(value), ""};
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                if (value.empty() || value[0] == '-') {
                    return {T{}, "Negative value for uint64_t: " + value};
                }
                return {std::stoull(value), ""};
            } else if constexpr (std::is_same_v<T, float>) {
                return {std::stof(value), ""};
            } else if constexpr (std::is_same_v<T, double>) {
                return {std::stod(value), ""};
            }
        } catch (const std::exception& e) {
            return {T{}, "Conversion error for '" + key + "': " + e.what()};
        }
        
        return {T{}, "Unsupported type for parameter '" + key + "'"};
    }

    // Required parameter - throws if missing or invalid
    template<typename T>
    [[nodiscard]] T require(const std::string& key) const {
        auto [value, error] = get<T>(key);
        if (!error.empty()) {
            throw std::invalid_argument("Required parameter '" + key + "' is missing or invalid: " + error);
        }
        return value;
    }
    
    // Parameter with default value
    template<typename T>
    [[nodiscard]] T get_or(const std::string& key, const T& default_value) const {
        auto [value, error] = get<T>(key);
        return error.empty() ? value : default_value;
    }
    
    // Check if parameter exists (regardless of type conversion)
    [[nodiscard]] bool has(const std::string& key) const {
        auto it = params_.find(key);
        return it != params_.end() && !it->second.empty();
    }
    
    // Get raw string value (no conversion)
    [[nodiscard]] std::string raw(const std::string& key) const {
        auto it = params_.find(key);
        return (it != params_.end()) ? it->second : "";
    }
};

struct RequestContext {
    App& app;
    std::shared_ptr<Connection> conn;
    const HttpRequest& req;

    template<typename T = std::string>
    [[nodiscard]] std::pair<T, std::string> query(const std::string& key) const {
        QueryParams q(req.query_params);
        return q.get<T>(key);
    }

    template<typename T = std::string>
    [[nodiscard]] std::pair<T, std::string> param(const std::string& key) const {
        return req.param<T>(key);
    }

    [[nodiscard]] QueryParams query() const {
        return QueryParams(req.query_params);
    }

    [[nodiscard]] std::pair<json, std::string> json_body() const {
        if (req.body.empty()) {
            return {json{}, "Request body is empty"};
        }
        
        try {
            return {json::parse(req.body), ""};
        } catch (const json::parse_error& e) {
            return {json{}, "JSON parse error: " + std::string(e.what())};
        }
    }

    template<typename T = std::string>
    [[nodiscard]] std::pair<T, std::string> json_field(const std::string& key) const {
        auto [body, parse_error] = json_body();
        if (!parse_error.empty()) {
            return {T{}, parse_error};
        }
        
        if (!body.contains(key)) {
            return {T{}, "JSON field '" + key + "' not found"};
        }
        
        try {
            if constexpr (std::is_same_v<T, std::string>) {
                if (body[key].is_string()) {
                    return {body[key].get<std::string>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not a string"};
                }
            } else if constexpr (std::is_same_v<T, bool>) {
                if (body[key].is_boolean()) {
                    return {body[key].get<bool>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not a boolean"};
                }
            } else if constexpr (std::is_same_v<T, int32_t>) {
                if (body[key].is_number_integer()) {
                    auto val = body[key].get<int64_t>();
                    if (val < std::numeric_limits<int32_t>::min() || val > std::numeric_limits<int32_t>::max()) {
                        return {T{}, "Field '" + key + "' out of range for int32_t"};
                    }
                    return {static_cast<int32_t>(val), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not an integer"};
                }
            } else if constexpr (std::is_same_v<T, uint32_t>) {
                if (body[key].is_number_unsigned()) {
                    auto val = body[key].get<uint64_t>();
                    if (val > std::numeric_limits<uint32_t>::max()) {
                        return {T{}, "Field '" + key + "' out of range for uint32_t"};
                    }
                    return {static_cast<uint32_t>(val), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not an unsigned integer"};
                }
            } else if constexpr (std::is_same_v<T, int64_t>) {
                if (body[key].is_number_integer()) {
                    return {body[key].get<int64_t>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not an integer"};
                }
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                if (body[key].is_number_unsigned()) {
                    return {body[key].get<uint64_t>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not an unsigned integer"};
                }
            } else if constexpr (std::is_same_v<T, float>) {
                if (body[key].is_number()) {
                    return {body[key].get<float>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not a number"};
                }
            } else if constexpr (std::is_same_v<T, double>) {
                if (body[key].is_number()) {
                    return {body[key].get<double>(), ""};
                } else {
                    return {T{}, "Field '" + key + "' is not a number"};
                }
            } else if constexpr (std::is_same_v<T, json>) {
                return {body[key], ""};  // Return the json object directly
            }
            
            return {T{}, "Unsupported type for JSON field '" + key + "'"};
        } catch (const json::exception& e) {
            return {T{}, "JSON conversion error for field '" + key + "': " + e.what()};
        }
    }

    asio::awaitable<SSEStream*> setup_sse(const std::string& stream_name) const {
        return ::setup_sse(app, conn, stream_name);
    }

    asio::awaitable<void> serve_static_file(std::string path) const {
        return ::serve_static_file(conn, std::move(path));
    }

 [[nodiscard]] MultipartParser::ParseResult multipart() const {
    return req.parse_multipart();
}

[[nodiscard]] std::string multipart_field(const std::string& name) const {
    auto result = req.parse_multipart();
    if (!result.success()) return "";
    return result.get_field(name);
}

[[nodiscard]] const MultipartFile* multipart_file(const std::string& name) const {
    static thread_local MultipartParser::ParseResult cached_result;
    static thread_local const HttpRequest* cached_req = nullptr;
    
    // Simple caching to avoid reparsing for multiple file accesses
    if (cached_req != &req) {
        cached_result = req.parse_multipart();
        cached_req = &req;
    }
    
    if (!cached_result.success()) return nullptr;
    return cached_result.get_file(name);
}

template<typename T = std::string>
[[nodiscard]] std::pair<T, std::string> multipart_field_typed(const std::string& name) const {
    auto result = req.parse_multipart();
    if (!result.success()) {
        return {T{}, "Multipart parsing failed: " + result.error};
    }
    
    std::string value = result.get_field(name);
    if (value.empty()) {
        return {T{}, "Field '" + name + "' not found"};
    }
    
    try {
        if constexpr (std::is_same_v<T, std::string>) {
            return {value, ""};
        } else if constexpr (std::is_same_v<T, bool>) {
            std::string lower_val = value;
            std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(), ::tolower);
            if (lower_val == "true" || lower_val == "1" || lower_val == "yes") {
                return {true, ""};
            } else if (lower_val == "false" || lower_val == "0" || lower_val == "no") {
                return {false, ""};
            }
            return {T{}, "Invalid boolean value: " + value};
        } else if constexpr (std::is_same_v<T, int32_t>) {
            long long temp_val = std::stoll(value);
            if (temp_val < std::numeric_limits<int32_t>::min() || temp_val > std::numeric_limits<int32_t>::max()) {
                return {T{}, "Value out of range for int32_t: " + value};
            }
            return {static_cast<int32_t>(temp_val), ""};
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            if (value.empty() || value[0] == '-') {
                return {T{}, "Negative value for uint32_t: " + value};
            }
            unsigned long long temp_val = std::stoull(value);
            if (temp_val > std::numeric_limits<uint32_t>::max()) {
                return {T{}, "Value out of range for uint32_t: " + value};
            }
            return {static_cast<uint32_t>(temp_val), ""};
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return {std::stoll(value), ""};
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            if (value.empty() || value[0] == '-') {
                return {T{}, "Negative value for uint64_t: " + value};
            }
            return {std::stoull(value), ""};
        } else if constexpr (std::is_same_v<T, float>) {
            return {std::stof(value), ""};
        } else if constexpr (std::is_same_v<T, double>) {
            return {std::stod(value), ""};
        }
        
        return {T{}, "Unsupported type for multipart field '" + name + "'"};
    } catch (const std::exception& e) {
        return {T{}, "Conversion error for field '" + name + "': " + e.what()};
    }
}

    asio::awaitable<Response> download_file(const std::string& file_path, const std::string& download_name = "") const {
        co_return ::download_file(file_path, download_name);
    }
    
    asio::awaitable<Response> serve_file_inline(const std::string& file_path, const std::string& display_name = "") const {
        co_return ::serve_file(file_path, display_name);
    }
};

// Validation helper class for complex parameter requirements
class ParamValidator {
public:
    struct ValidationError {
        std::string field;
        std::string message;
    };
    
private:
    std::vector<ValidationError> errors_;
    
public:
    template<typename T>
    ParamValidator& require_query(const QueryParams& query, const std::string& key, T& out_value, const std::string& error_msg = "") {
        auto [value, error] = query.get<T>(key);
        if (!error.empty()) {
            std::string msg = error_msg.empty() ? 
                std::format("Required query parameter '{}' is missing or invalid", key) : 
                error_msg;
            errors_.push_back({key, msg});
        } else {
            out_value = value;
        }
        return *this;
    }
    
    template<typename T>
    ParamValidator& require_param(const RequestContext& ctx, const std::string& key, T& out_value, const std::string& error_msg = "") {
        auto [value, error] = ctx.param<T>(key);
        if (!error.empty()) {
            std::string msg = error_msg.empty() ? 
                std::format("Required route parameter '{}' is missing or invalid", key) : 
                error_msg;
            errors_.push_back({key, msg});
        } else {
            out_value = value;
        }
        return *this;
    }
    
    template<typename T>
    ParamValidator& validate_range(const T& value, const std::string& field, const T& min_val, const T& max_val) {
        if (value < min_val || value > max_val) {
            errors_.push_back({field, std::format("{} must be between {} and {}", field, min_val, max_val)});
        }
        return *this;
    }
    
    ParamValidator& validate_not_empty(const std::string& value, const std::string& field) {
        if (value.empty()) {
            errors_.push_back({field, std::format("{} cannot be empty", field)});
        }
        return *this;
    }
    
    ParamValidator& validate_max_length(const std::string& value, const std::string& field, size_t max_len) {
        if (value.length() > max_len) {
            errors_.push_back({field, std::format("{} cannot exceed {} characters", field, max_len)});
        }
        return *this;
    }
    
    [[nodiscard]] bool is_valid() const {
        return errors_.empty();
    }
    
    [[nodiscard]] Response validation_error_response() const {
        json error_json = {{"error", "Validation failed"}, {"details", json::array()}};
        for (const auto& error : errors_) {
            error_json["details"].push_back({{"field", error.field}, {"message", error.message}});
        }
        return Response(400).json(error_json);
    }
    
    [[nodiscard]] const std::vector<ValidationError>& errors() const {
        return errors_;
    }
};

using Handler = std::function<asio::awaitable<Response>(const RequestContext&)>;
using NextFunction = std::function<asio::awaitable<Response>()>;
using Middleware = std::function<asio::awaitable<Response>(const RequestContext&, NextFunction)>;

struct SSEEvent {
    std::string data;
    std::string event_type;
    std::string id;
    int32_t retry = -1;
    
    [[nodiscard]] std::string to_string() const {
        std::string result;
        
        if (!event_type.empty()) {
            std::format_to(std::back_inserter(result), "event: {}\n", event_type);
        }

        if (!id.empty()) {
            std::format_to(std::back_inserter(result), "id: {}\n", id);
        }

        if (retry >= 0) {
            std::format_to(std::back_inserter(result), "retry: {}\n", retry);
        }

        std::format_to(std::back_inserter(result), "data: {}\n\n", data);
        return result;
    }
};

class SSEStream {
    public:
        explicit SSEStream(std::string_view name) : stream_name_(name) {}
        explicit SSEStream(std::string_view name, asio::io_context& io_ctx) : stream_name_(name), io_context_(&io_ctx) {}
        void on_connect(std::function<void(std::shared_ptr<Connection>)> handler) { on_connect_ = std::move(handler); }
        void on_disconnect(std::function<void(std::shared_ptr<Connection>)> handler) { on_disconnect_ = std::move(handler); }
        void add_connection(const std::shared_ptr<Connection>& conn);
        void remove_connection(const std::shared_ptr<Connection>& conn);
        
        asio::awaitable<void> broadcast(const SSEEvent& event);
        asio::awaitable<void> broadcast_to(const SSEEvent& event, std::function<bool(std::shared_ptr<Connection>)> filter);
        asio::awaitable<void> send_to(std::shared_ptr<Connection> conn, const SSEEvent& event);
        
        size_t connection_count() const { 
            std::lock_guard<std::mutex> lock(connections_mutex_);
            return connections_.size(); 
        }

        std::string_view name() const { 
            return stream_name_; 
        }

        std::vector<std::shared_ptr<Connection>> get_connections() const {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            return connections_;
        }

        void broadcast_async(const SSEEvent& event) {
            asio::co_spawn(*io_context_, broadcast(event), asio::detached);
        }
        
        void broadcast_to_async(const SSEEvent& event, std::function<bool(std::shared_ptr<Connection>)> filter) {
            asio::co_spawn(*io_context_, broadcast_to(event, std::move(filter)), asio::detached);
        }
        
        void send_to_async(std::shared_ptr<Connection> conn, const SSEEvent& event) {
            asio::co_spawn(*io_context_, send_to(std::move(conn), event), asio::detached);
        }
        
        // Convenience methods for common patterns
        void send_message(std::shared_ptr<Connection> conn, const std::string& message, const std::string& event_type = "") {
            SSEEvent event;
            event.data = message;
            event.event_type = event_type;
            send_to_async(std::move(conn), event);
        }
        
        void broadcast_message(const std::string& message, const std::string& event_type = "") {
            SSEEvent event;
            event.data = message;
            event.event_type = event_type;
            broadcast_async(event);
        }

    private:
        std::vector<std::shared_ptr<Connection>> connections_;
        std::string stream_name_;
        std::function<void(std::shared_ptr<Connection>)> on_connect_;
        std::function<void(std::shared_ptr<Connection>)> on_disconnect_;
        mutable std::mutex connections_mutex_;
        asio::io_context* io_context_{};
};

class SSEManager {
    public:
    explicit SSEManager(asio::io_context& io_ctx) : io_context_(&io_ctx) {}
    
    SSEStream* create_stream(const std::string& name) {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        if (streams_.contains(name)) {
            return streams_[name].get();
        }
        std::unique_ptr<SSEStream> stream = std::make_unique<SSEStream>(name, *io_context_);
        SSEStream* ptr = stream.get();
        streams_[name] = std::move(stream);
        return ptr;
    }
    
    SSEStream* get_stream(const std::string& name) {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(name);
        return (it != streams_.end()) ? it->second.get() : nullptr;
    }

    private:
        std::unordered_map<std::string, std::unique_ptr<SSEStream>> streams_;
        mutable std::mutex streams_mutex_;
        asio::io_context* io_context_;
};

struct Connection {
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;

    // Metadata and tag management methods
    void add_tag(const std::string& tag) { 
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        tags.insert(tag); 
    }

    bool has_tag(const std::string& tag) const { 
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        return tags.contains(tag); 
    }
    
    void set_metadata(const std::string& key, const std::string& value) { 
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        metadata[key] = value; 
    }
    
    std::string get_metadata(const std::string& key) const {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        auto it = metadata.find(key);
        return (it != metadata.end()) ? it->second : "";
    }

    asio::ip::tcp::socket socket;
    std::unique_ptr<asio::steady_timer> keep_alive_timer;
    std::string endpoint;
    asio::streambuf buffer;
    std::array<char, 1> dummy_buffer{};
    std::atomic<bool> is_connected{true};
    std::atomic<bool> is_sse_connection{false};

    // SSE-specific metadata for your handlers
    std::unordered_set<std::string> tags;
    std::unordered_map<std::string, std::string> metadata;
    mutable std::mutex metadata_mutex_;
    
    Connection(asio::ip::tcp::socket socket_arg) : socket(std::move(socket_arg)) {
        keep_alive_timer = std::make_unique<asio::steady_timer>(socket.get_executor());
        asio::error_code ec;
        asio::ip::tcp::endpoint ep = socket.remote_endpoint(ec);

        if (ec) {
            std::println("Error getting endpoint: {}", ec.message());
            endpoint = "unknown";
        }

        if (socket.is_open()) {
            if (ep.address().is_v4()) {
                endpoint = std::format("{}:{}", ep.address().to_string(), ep.port());
            } else {
                endpoint = std::format("[{}]:{}", ep.address().to_string(), ep.port());
            }
        }
        
    }
};

// Routing data structures
struct PathSegment {
    std::string value;
    bool is_parameter = false;
    std::string param_type = "string";
};

struct RouteInfo {
    HttpMethod method{};
    std::vector<PathSegment> segments;
    Handler handler;
};

class ConnectionRegistry {
public:
    void register_connection(const std::shared_ptr<Connection>& conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_[conn->endpoint] = conn;
    }
    
    void unregister_connection(const std::string& endpoint) {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_.erase(endpoint);
    }
    
    std::shared_ptr<Connection> find_connection(const std::string& endpoint) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(endpoint);
        if (it != connections_.end()) {
            if (std::shared_ptr<Connection> conn = it->second.lock()) {
                return conn;
            } else {
                connections_.erase(it); 
            }
        }
        return nullptr;
    }
    
private:
    std::unordered_map<std::string, std::weak_ptr<Connection>> connections_;
    std::mutex mutex_;
};

struct App {
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor;
    std::vector<RouteInfo> routes;
    std::vector<Middleware> middlewares;
    SSEManager sse_manager;
    ConnectionRegistry connection_registry;
    
    App(uint16_t port) : acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)), sse_manager(io_context) {
        #ifdef _WIN32
        acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        #endif
    }
    
    SSEStream* create_sse_stream(const std::string& name) { return sse_manager.create_stream(name); }
    
    void Get(std::string_view path, Handler&& handler) { route(path, HttpMethod::GET, std::move(handler)); }
    void Post(std::string_view path, Handler&& handler) { route(path, HttpMethod::POST, std::move(handler)); }
    void Put(std::string_view path, Handler&& handler) { route(path, HttpMethod::PUT, std::move(handler)); }
    void Delete(std::string_view path, Handler&& handler) { route(path, HttpMethod::DELETE, std::move(handler)); }
    void Patch(std::string_view path, Handler&& handler) { route(path, HttpMethod::PATCH, std::move(handler)); }
    void Options(std::string_view path, Handler&& handler) { route(path, HttpMethod::OPTIONS, std::move(handler)); }
    
    void use(Middleware middleware) { middlewares.emplace_back(std::move(middleware)); }
    
    void run() {
        try {
            asio::co_spawn(io_context, [this] { 
                return start_accept(); 
            }, asio::detached);
            
            std::println("Server running on port {}...", acceptor.local_endpoint().port());
            io_context.run();
        } catch (const std::exception &e) {
            std::println("Server run error: {}", e.what());
        }
    }

private:
    asio::awaitable<void> start_accept() {
        for (;;) {
            auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
            if (!ec) {
                std::shared_ptr<Connection> conn = std::make_shared<Connection>(std::move(socket));
                connection_registry.register_connection(conn);
                asio::co_spawn(io_context, handle_request(*this, conn), asio::detached);
            } else {
                std::println("Accept error: {}", ec.message());
            }
        }
    }

    void route(std::string_view path, HttpMethod method, Handler&& handler) {
        RouteInfo route_info;
        route_info.method = method;
        route_info.handler = std::move(handler);

        std::string current_segment;
        std::istringstream stream{std::string(path)};

        while (std::getline(stream, current_segment, '/')) {
            if (current_segment.empty()) continue;

            PathSegment segment;
            if (current_segment.starts_with(':')) {
                segment.is_parameter = true;
                size_t type_start = current_segment.find('<');
                if (type_start != std::string::npos) {
                    size_t type_end = current_segment.find('>');
                    if (type_end != std::string::npos) {
                        segment.param_type = current_segment.substr(type_start + 1, type_end - type_start - 1);
                        segment.value = current_segment.substr(1, type_start - 1);
                    }
                } else {
                    segment.value = current_segment.substr(1);
                }
            } else {
                segment.value = current_segment;
            }
            route_info.segments.emplace_back(std::move(segment));
        }
        routes.emplace_back(std::move(route_info));
    }
};

void SSEStream::add_connection(const std::shared_ptr<Connection>& conn) {
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.emplace_back(conn);
    }
    conn->is_sse_connection = true;
    if (on_connect_) on_connect_(conn);
    std::println("SSE Stream '{}': Added connection {} (total: {})", stream_name_, conn->endpoint, connection_count());
}

void SSEStream::remove_connection(const std::shared_ptr<Connection>& conn) {
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = std::find(connections_.begin(), connections_.end(), conn);
        if (it != connections_.end()) {
            connections_.erase(it);
            found = true;
        }
    }
    if (found) {
        if (on_disconnect_) on_disconnect_(conn);
        std::println("SSE Stream '{}': Removed connection {} (total: {})", stream_name_, conn->endpoint, connection_count());
    }
}

asio::awaitable<void> SSEStream::broadcast(const SSEEvent& event) {
    std::string event_str = event.to_string();
    std::vector<std::shared_ptr<Connection>> connections_copy;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_copy = connections_;
    }
    for (const std::shared_ptr<Connection>& conn : connections_copy) {
        if (!conn->socket.is_open() || !conn->is_connected.load()) continue;
        try {
            co_await asio::async_write(conn->socket, asio::buffer(event_str), asio::use_awaitable);
        } catch (const std::exception& e) {
            std::println("Broadcast error to {}: {}", conn->endpoint, e.what());
            conn->is_connected = false;
        }
    }
}

asio::awaitable<void> SSEStream::broadcast_to(const SSEEvent& event, std::function<bool(std::shared_ptr<Connection>)> filter) {
    std::string event_str = event.to_string();
    std::vector<std::shared_ptr<Connection>> connections_copy;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_copy = connections_;
    }
    for (const std::shared_ptr<Connection>& conn : connections_copy) {
        if (!conn->socket.is_open() || !conn->is_connected.load() || !filter(conn)) continue;
        try {
            co_await asio::async_write(conn->socket, asio::buffer(event_str), asio::use_awaitable);
        } catch (const std::exception& e) {
            std::println("Targeted broadcast error to {}: {}", conn->endpoint, e.what());
            conn->is_connected = false;
        }
    }
}

asio::awaitable<void> SSEStream::send_to(std::shared_ptr<Connection> conn, const SSEEvent& event) {
    if (!conn->socket.is_open() || !conn->is_connected.load()) co_return;
    try {
        co_await asio::async_write(conn->socket, asio::buffer(event.to_string()), asio::use_awaitable);
    } catch (const std::exception& e) {
        std::println("Send error to {}: {}", conn->endpoint, e.what());
        conn->is_connected = false;
        remove_connection(conn);
    }
}

asio::awaitable<void> send_sse_headers(std::shared_ptr<Connection> conn) {
    std::string headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";
        
    co_await asio::async_write(conn->socket, asio::buffer(headers), asio::use_awaitable);
}

// Route matching function with URL decoding
std::pair<Handler, std::unordered_map<std::string, RouteParamVariant>> find_route(const App& app, HttpMethod method, const std::string& path) {
    std::vector<std::string> request_segments;
    std::string current_segment;
    std::istringstream stream{path};
    while (std::getline(stream, current_segment, '/')) {
        if (!current_segment.empty() && current_segment != "..") {
            request_segments.emplace_back(url_decode(current_segment));  // URL decode each segment
        }
    }

    for (const RouteInfo& route_info : app.routes) {
        if (route_info.method != method || route_info.segments.size() != request_segments.size()) {
            continue;
        }

        std::unordered_map<std::string, RouteParamVariant> params;
        bool match = true;
        for (size_t i = 0; i < route_info.segments.size(); ++i) {
            const PathSegment& route_segment = route_info.segments[i];
            const std::string& request_segment = request_segments[i]; // Already URL decoded
            if (route_segment.is_parameter) {
                if (request_segment.length() > 256) {
                     params[route_segment.value] = std::string("_param_conversion_failed_");
                } else {
                    try {
                        if (route_segment.param_type == "string") {
                            params[route_segment.value] = request_segment;
                        } else if (route_segment.param_type == "bool") {
                            std::string lower_req = request_segment;
                            std::transform(lower_req.begin(), lower_req.end(), lower_req.begin(), ::tolower);
                            if (lower_req == "true" || lower_req == "1") {
                                params[route_segment.value] = true;
                            } else if (lower_req == "false" || lower_req == "0") {
                                params[route_segment.value] = false;
                            } else {
                                throw std::invalid_argument("Invalid boolean string");
                            }
                         } else if (route_segment.param_type == "uint32") {
                            if (request_segment.empty() || request_segment[0] == '-') {
                                throw std::out_of_range("Negative value for uint32");
                            }
                            long long temp_val = std::stoll(request_segment);
                            if (temp_val < 0 || temp_val > std::numeric_limits<uint32_t>::max()) {
                                throw std::out_of_range("Value out of range for uint32");
                            }
                            params[route_segment.value] = static_cast<uint32_t>(temp_val);
                         } else if (route_segment.param_type == "uint64") {
                            if (request_segment.empty() || request_segment[0] == '-') {
                                throw std::out_of_range("Negative value for uint64");
                            }
                            for (char c : request_segment) {
                                if (!std::isdigit(c)) {
                                     throw std::invalid_argument("Invalid character for uint64");
                                }
                            }
                            params[route_segment.value] = std::stoull(request_segment);
                         } else if (route_segment.param_type == "int32") {
                            long long temp_val = std::stoll(request_segment);
                            if (temp_val < std::numeric_limits<int32_t>::min() || temp_val > std::numeric_limits<int32_t>::max()) {
                                 throw std::out_of_range("Value out of range for int32");
                            }
                            params[route_segment.value] = static_cast<int32_t>(temp_val);
                         } else if (route_segment.param_type == "int64") {
                            params[route_segment.value] = std::stoll(request_segment);
                        } else if (route_segment.param_type == "float") {
                            params[route_segment.value] = std::stof(request_segment);
                        } else if (route_segment.param_type == "double") {
                            params[route_segment.value] = std::stod(request_segment);
                        } else {
                            params[route_segment.value] = request_segment;
                        }
                    } catch (const std::exception&) {
                        params[route_segment.value] = std::string("_param_conversion_failed_");
                    }
                }
            } else if (route_segment.value != request_segment) {
                match = false;
                break;
            }
        }

        if (match) {
            return {route_info.handler, params};
        }
    }
    return {nullptr, {}};
}

asio::awaitable<Response> execute_middleware_chain(const RequestContext& ctx, const Handler &final_handler,
                                                   const std::vector<Middleware> &middleware_chain, size_t index) {
    if (index >= middleware_chain.size()) {
        co_return co_await final_handler(ctx);
    }
    NextFunction next = [&, index]() {
        return execute_middleware_chain(ctx, final_handler, middleware_chain, index + 1);
    };
    co_return co_await middleware_chain[index](ctx, next);
}

asio::awaitable<void> handle_request(App &app, std::shared_ptr<Connection> conn) {
    try {
        auto [ec, bytes_read] = co_await asio::async_read_until(conn->socket, conn->buffer, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::eof) std::println("Read error: {}", ec.message());
            co_return;
        }

        // Parse headers only first
        HttpRequest req = HttpRequest::parse_headers(conn->buffer);
        
        // Read full body if Content-Length exists
        if (req.headers.contains("Content-Length")) {
            size_t content_length = std::stoul(req.headers["Content-Length"]);
            req.body.resize(content_length);
            
            // Read from buffer first
            size_t buffered = conn->buffer.size();
            if (buffered > 0) {
                size_t to_copy = std::min(buffered, content_length);
                asio::buffer_copy(asio::buffer(req.body.data(), to_copy), 
                                 conn->buffer.data());
                conn->buffer.consume(to_copy);
            }

            // Read remaining directly from socket
            size_t remaining = content_length - buffered;
            if (remaining > 0) {
                asio::error_code read_ec;
                co_await asio::async_read(conn->socket,
                    asio::buffer(req.body.data() + buffered, remaining),
                    asio::transfer_exactly(remaining),
                    asio::redirect_error(asio::use_awaitable, read_ec));
                if (read_ec) {
                    std::println("Body read error: {}", read_ec.message());
                    co_return;
                }
            }
        }
        
        auto [final_handler, params] = find_route(app, req.method, req.path);
        req.params = std::move(params);

        if (!final_handler) {
            if (req.method == HttpMethod::GET) {
                // Only serve static files for paths that look like files (have extensions)
                std::string path = req.path.substr(req.path.find_first_not_of('/'));
                if (!path.empty() && path.find('.') != std::string::npos) {
                    co_await serve_static_file(conn, path);
                    co_return;
                } else {
                    final_handler = [](const RequestContext&) -> asio::awaitable<Response> {
                        co_return not_found("Route not found");
                    };
                }
            } else {
                final_handler = [](const RequestContext&) -> asio::awaitable<Response> {
                    co_return not_found();
                };
            }
        }
        
        // Create the context object that bundles all request data
        RequestContext ctx{app, conn, req};

        // Pass the context to the middleware chain
        Response res = co_await execute_middleware_chain(ctx, final_handler, app.middlewares, 0);
        
        // Don't send a response if the handler was for an SSE connection or another reason
        if (res.should_send() && !conn->is_sse_connection) {
            co_await send_response(conn, res.build());
        }
    } catch (const std::exception &e) {
        std::println("Request handling exception: {}", e.what());
    }
}

asio::awaitable<SSEStream*> setup_sse(App& app, std::shared_ptr<Connection> conn, const std::string& stream_name) {
    co_await send_sse_headers(conn);

    SSEStream* stream = app.sse_manager.get_stream(stream_name);
    if (!stream) {
        stream = app.sse_manager.create_stream(stream_name);
    }

    stream->add_connection(conn);

    asio::co_spawn(conn->socket.get_executor(), [&app, conn, stream]() -> asio::awaitable<void> {
            try {
                co_await start_disconnection_detection(app, conn);
            } catch (const std::exception& e) {
                std::println("Disconnection detection error: {}", e.what());
            }

            stream->remove_connection(conn);
            app.connection_registry.unregister_connection(conn->endpoint);
        }, asio::detached);

    co_return stream;
}

asio::awaitable<void> send_response(std::shared_ptr<Connection> conn, const HttpResponse &res) {
    try {
        co_await asio::async_write(conn->socket, asio::buffer(res.to_string()), asio::use_awaitable);
        if (res.headers.contains("Connection") && res.headers.at("Connection") == "close") {
            conn->socket.close();
        }
    } catch (const std::exception& e) {
        std::println("Send response error: {}", e.what());
        conn->socket.close();
    }
}

asio::awaitable<void> serve_static_file(std::shared_ptr<Connection> conn, std::string path) {
    Response res = not_found("<h1>404 Not Found</h1>").html("<h1>404 Not Found</h1>");
    
    if (path.find("..") != std::string::npos) {
        res = Response(403).text("Forbidden");
    } else {
        std::string file_path = path.empty() ? "index.html" : path;
        if (fs::exists(file_path) && fs::is_regular_file(file_path)) {
            std::ifstream file(file_path, std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            std::string ext = fs::path(file_path).extension().string();
            std::string content_type = MIME_TYPES.contains(ext) ? MIME_TYPES.at(ext) : "application/octet-stream";
            
            res = Response(content).header("Content-Type", content_type);
        }
    }
    co_await send_response(conn, res.build());
}

asio::awaitable<void> start_disconnection_detection(App &app, std::shared_ptr<Connection> conn) {
    try {
        asio::co_spawn(conn->socket.get_executor(), [conn]() -> asio::awaitable<void> {
            asio::steady_timer timer(conn->socket.get_executor());

            while (conn->socket.is_open() && conn->is_connected.load()) {
                timer.expires_after(std::chrono::seconds(1));
                asio::error_code timer_ec;
                
                co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, timer_ec));
                
                if (!conn->is_connected.load() || timer_ec) {
                    break;
                }
                
                asio::error_code write_ec;
                co_await asio::async_write(conn->socket, asio::buffer(std::string(": keepalive\n\n")),
                    asio::redirect_error(asio::use_awaitable, write_ec)
                );
                
                if (write_ec) {
                    std::println("Keepalive failed for {}: {}", conn->endpoint, write_ec.message());
                    conn->is_connected = false;
                    break;
                }
            }
        }, asio::detached);
        
        while (conn->socket.is_open() && conn->is_connected.load()) {
            asio::error_code ec;
            co_await conn->socket.async_read_some(asio::buffer(conn->dummy_buffer), asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                conn->is_connected = false;
                break;
            }
        }
    } catch (const std::exception&) {
        conn->is_connected = false;
    }
}

asio::awaitable<Response> logging_middleware(const RequestContext& ctx, NextFunction next) {
    std::println("[{}] {} {}", ctx.conn->endpoint, to_string(ctx.req.method), ctx.req.full_path);  
    co_return co_await next();
}

asio::awaitable<Response> notifications_handler(const RequestContext& ctx) {
    SSEStream* stream = co_await ctx.setup_sse("notifications");

    SSEEvent welcome;
    welcome.event_type = "welcome";
    welcome.data = json{{"message", "Connected to notifications"}}.dump();
    co_await stream->send_to(ctx.conn, welcome);

    co_return Response::no_response();
}

asio::awaitable<Response> chat_page_handler(const RequestContext& ctx) {
    co_await ctx.serve_static_file("sse.html");
    co_return Response::no_response();
}

asio::awaitable<Response> chat_stream_handler(const RequestContext& ctx) {
    auto [username, error] = ctx.query<std::string>("username");
    if (!error.empty()) {
        co_return bad_request(std::format("Username is required: {}", error));
    }

    SSEStream* stream = ctx.app.sse_manager.get_stream("chat_general");

    if (stream) {
        for (const std::shared_ptr<Connection>& c : stream->get_connections()) {
            if (c->get_metadata("username") == username) {
                HttpResponse error_res;
                error_res.status = "409 Conflict";
                error_res.headers["Content-Type"] = "application/json";
                error_res.headers["Connection"] = "close";
                error_res.body = json{{"error", "Username is already taken."}}.dump();
                co_await send_response(ctx.conn, error_res);
                co_return Response::no_response();
            }
        }
    }

    stream = co_await ctx.setup_sse("chat_general");

    stream->on_disconnect([stream](const std::shared_ptr<Connection>& c) {
        std::string disconnected_user = c->get_metadata("username");
        if (!disconnected_user.empty()) {
            json disconnect_msg = {{"type", "user_disconnected"}, {"user", disconnected_user}};
            stream->broadcast_message(disconnect_msg.dump());
        }
    });

    ctx.conn->set_metadata("username", username);
    ctx.conn->add_tag("chat_user");

    std::vector<std::string> users;
    for (const std::shared_ptr<Connection>& c : stream->get_connections()) {
        if (std::string user = c->get_metadata("username"); !user.empty()) {
            users.emplace_back(user);
        }
    }

    SSEEvent welcome_event;
    welcome_event.data = json{{"type", "welcome"}, {"user", username}, {"users", users}}.dump();
    co_await stream->send_to(ctx.conn, welcome_event);

    SSEEvent user_connected_event;
    user_connected_event.data = json{{"type", "user_connected"}, {"user", username}}.dump();
    co_await stream->broadcast_to(user_connected_event, [conn = ctx.conn](const std::shared_ptr<Connection>& c) {
        return c != conn && c->has_tag("chat_user");
    });

    co_return Response::no_response();
}

// Helper to sanitize filenames for security
std::string sanitize_filename(const std::string& filename) {
    std::string sanitized = filename;
    
    // Replace potentially harmful characters with an underscore
    std::string forbidden_chars = "/\\:*?\"<>|";
    for (char& c : sanitized) {
        if (forbidden_chars.find(c) != std::string::npos) {
            c = '_';
        }
    }
    
    // Remove ".." sequences to prevent path traversal attacks
    size_t pos = 0;
    while ((pos = sanitized.find("..")) != std::string::npos) {
        sanitized.erase(pos, 2);
    }
    
    // Limit the overall length to a reasonable number
    if (sanitized.length() > 200) {
        sanitized.resize(200);
    }
    
    return sanitized;
}

asio::awaitable<Response> chat_upload_handler(const RequestContext& ctx) {
    if (!ctx.req.is_multipart()) {
        co_return bad_request("Request must be multipart/form-data");
    }

    auto multipart = ctx.multipart();
    if (!multipart.success()) {
        co_return bad_request("Failed to parse multipart data: " + multipart.error);
    }

    auto username = multipart.get_field("username");
    const MultipartFile* file = multipart.get_file("file");

    if (username.empty()) {
        co_return bad_request("Username is required.");
    }
    if (!file) {
        co_return bad_request("File data is missing.");
    }
    if (file->empty()) {
        co_return bad_request("File cannot be empty.");
    }
    if (file->size() > 50 * 1024 * 1024) { // 50MB limit
        co_return bad_request("File is too large (max 50MB)");
    }

    std::string upload_dir = "uploads";
    if (!fs::exists(upload_dir)) {
        fs::create_directory(upload_dir);
    }

    std::string sanitized_name = sanitize_filename(file->filename);
    std::string timestamp = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    std::string unique_filename = timestamp + "_" + sanitized_name;
    std::string save_path = upload_dir + "/" + unique_filename;

    if (!file->save_to(save_path)) {
        co_return error(500).json({{"error", "Failed to save file on server"}});
    }

    SSEStream* stream = ctx.app.sse_manager.get_stream("chat_general");
    if (!stream) {
        co_return not_found("Chat room not found. Cannot broadcast file.");
    }

    bool is_image = file->content_type.rfind("image/", 0) == 0;
    std::string file_type = is_image ? "image" : "file";

    SSEEvent file_event;
    file_event.data = json{
        {"type", "file_message"},
        {"user", username},
        {"original_name", file->filename},
        {"url", "/uploads/" + unique_filename},
        {"file_type", file_type}
    }.dump();

    co_await stream->broadcast(file_event);

    co_return success({{"status", "uploaded"}, {"path", save_path}});
}


asio::awaitable<Response> request_private_chat_handler(const RequestContext& ctx) {
    SSEStream* public_stream = ctx.app.sse_manager.get_stream("chat_general");
    if (!public_stream) {
        co_return not_found("Public chat not found");
    }
    
    auto [from_user, from_error] = ctx.json_field<std::string>("from");
    auto [to_user, to_error] = ctx.json_field<std::string>("to");
    
    if (!from_error.empty()) {
        co_return bad_request("From user error: " + from_error);
    }
    if (!to_error.empty()) {
        co_return bad_request("To user error: " + to_error);
    }
    
    if (from_user.empty() || to_user.empty()) {
        co_return bad_request("Both 'from' and 'to' users are required");
    }
    
    if (from_user == to_user) {
        co_return bad_request("Cannot start private chat with yourself");
    }
    
    std::shared_ptr<Connection> from_conn = nullptr;
    std::shared_ptr<Connection> to_conn = nullptr;
    
    for (const std::shared_ptr<Connection>& c : public_stream->get_connections()) {
        std::string username = c->get_metadata("username");
        if (username == from_user) from_conn = c;
        else if (username == to_user) to_conn = c;
    }
    
    if (!from_conn) co_return error(403).json({{"error", "Requesting user not found in public chat"}});
    if (!to_conn) co_return error(404).json({{"error", "Target user not found in public chat"}});
    
    std::string request_id = from_user + "_to_" + to_user + "_" + 
                           std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch()).count());
    
    from_conn->set_metadata("pending_request_" + to_user, request_id);
    
    SSEEvent request_event;
    request_event.event_type = "private_chat_request";
    request_event.data = json{
        {"type", "private_chat_request"}, {"from", from_user}, {"to", to_user},
        {"request_id", request_id}, {"message", from_user + " wants to start a private chat with you"}
    }.dump();
    co_await public_stream->send_to(to_conn, request_event);
    
    SSEEvent confirm_event;
    confirm_event.event_type = "request_sent";
    confirm_event.data = json{
        {"type", "request_sent"}, {"to", to_user}, {"request_id", request_id},
        {"message", "Private chat request sent to " + to_user}
    }.dump();
    co_await public_stream->send_to(from_conn, confirm_event);
    
    co_return success({{"status", "request_sent"}, {"request_id", request_id}});
}

asio::awaitable<Response> respond_private_chat_handler(const RequestContext& ctx) {
    SSEStream* public_stream = ctx.app.sse_manager.get_stream("chat_general");
    if (!public_stream) co_return not_found("Public chat not found");
    
    auto [request_id, id_error] = ctx.json_field<std::string>("request_id");
    auto [response, response_error] = ctx.json_field<std::string>("response");
    auto [responding_user, user_error] = ctx.json_field<std::string>("user");
    
    if (!id_error.empty()) co_return bad_request("Request ID error: " + id_error);
    if (!response_error.empty()) co_return bad_request("Response error: " + response_error);
    if (!user_error.empty()) co_return bad_request("User error: " + user_error);
    
    if (response != "accept" && response != "decline") co_return bad_request("Response must be 'accept' or 'decline'");
    
    size_t to_pos = request_id.find("_to_");
    if (to_pos == std::string::npos) co_return bad_request("Invalid request ID format");
    
    std::string from_user = request_id.substr(0, to_pos);
    size_t timestamp_pos = request_id.find('_', to_pos + 4);
    if (timestamp_pos == std::string::npos) co_return bad_request("Invalid request ID format");
    std::string to_user = request_id.substr(to_pos + 4, timestamp_pos - to_pos - 4);
    
    if (responding_user != to_user) co_return error(403).json({{"error", "You can only respond to requests sent to you"}});
    
    std::shared_ptr<Connection> from_conn = nullptr;
    std::shared_ptr<Connection> to_conn = nullptr;
    
    for (const std::shared_ptr<Connection>& c : public_stream->get_connections()) {
        std::string username = c->get_metadata("username");
        if (username == from_user) from_conn = c;
        else if (username == to_user) to_conn = c;
    }
    
    if (!from_conn || !to_conn) co_return error(404).json({{"error", "One or both users are no longer connected"}});
    
    std::string stored_request = from_conn->get_metadata("pending_request_" + to_user);
    if (stored_request != request_id) co_return error(404).json({{"error", "Request not found or expired"}});
    
    from_conn->set_metadata("pending_request_" + to_user, "");
    
    if (response == "decline") {
        SSEEvent decline_event;
        decline_event.event_type = "private_chat_declined";
        decline_event.data = json{
            {"type", "private_chat_declined"}, {"from", from_user}, {"to", to_user},
            {"message", to_user + " declined the private chat request"}
        }.dump();
        
        co_await public_stream->send_to(from_conn, decline_event);
        co_await public_stream->send_to(to_conn, decline_event);
        co_return success({{"status", "declined"}});
    }
    
    std::string private_stream_name = "private_" + std::min(from_user, to_user) + "_" + std::max(from_user, to_user);
    SSEStream* existing_stream = ctx.app.sse_manager.get_stream(private_stream_name);
    if (existing_stream && existing_stream->connection_count() > 0) co_return error(409).json({{"error", "Private chat already exists"}});
    
    SSEStream* private_stream = ctx.app.sse_manager.create_stream(private_stream_name);
    private_stream->on_disconnect([private_stream, from_user, to_user](const std::shared_ptr<Connection>& c) {
        std::string disconnected_user = c->get_metadata("username");
        SSEEvent end_event;
        end_event.event_type = "private_chat_ended";
        end_event.data = json{
            {"type", "private_chat_ended"}, {"user", disconnected_user},
            {"message", disconnected_user + " left the private chat"}
        }.dump();
        private_stream->broadcast_message(end_event.to_string());
    });
    
    private_stream->add_connection(from_conn);
    private_stream->add_connection(to_conn);
    
    from_conn->add_tag("private_chat_" + private_stream_name);
    to_conn->add_tag("private_chat_" + private_stream_name);
    from_conn->set_metadata("private_stream", private_stream_name);
    to_conn->set_metadata("private_stream", private_stream_name);
    
    SSEEvent success_event;
    success_event.event_type = "private_chat_started";
    success_event.data = json{
        {"type", "private_chat_started"}, {"from", from_user}, {"to", to_user},
        {"stream_name", private_stream_name}, {"message", "Private chat started"}
    }.dump();
    co_await private_stream->broadcast(success_event);
    
    co_return success({{"status", "accepted"}, {"stream_name", private_stream_name}});
}

asio::awaitable<Response> send_private_message_handler(const RequestContext& ctx) {
    auto [from_user, from_error] = ctx.json_field<std::string>("from");
    auto [to_user, to_error] = ctx.json_field<std::string>("to");
    auto [message, message_error] = ctx.json_field<std::string>("message");
    
    if (!from_error.empty() || !to_error.empty() || !message_error.empty())
        co_return bad_request("From, to, and message are required.");
    
    std::string private_stream_name = "private_" + std::min(from_user, to_user) + "_" + std::max(from_user, to_user);
    SSEStream* private_stream = ctx.app.sse_manager.get_stream(private_stream_name);
    if (!private_stream) co_return not_found("Private chat not found.");
    
    bool sender_found = false;
    for (const std::shared_ptr<Connection>& c : private_stream->get_connections()) {
        if (c->get_metadata("username") == from_user) {
            sender_found = true;
            break;
        }
    }
    
    if (!sender_found) co_return error(403).json({{"error", "You are not part of this private chat"}});
    
    SSEEvent message_event;
    message_event.event_type = "private_message";
    message_event.data = json{
        {"type", "private_message"}, {"from", from_user}, {"to", to_user},
        {"message", message}, {"stream", private_stream_name}
    }.dump();
    co_await private_stream->broadcast(message_event);
    
    co_return success({{"status", "sent"}, {"stream", private_stream_name}});
}

asio::awaitable<Response> app_info_handler(const RequestContext&) {
    json data = {{"name", "My API"}, {"version", "1.0.1"}, {"url_decoding", "enabled"}};
    co_return success(data); 
};

asio::awaitable<Response> hello_param_handler(const RequestContext& ctx) {
    auto [name, error] = ctx.param<std::string>("name");  
    if (!error.empty()) co_return bad_request(error);
    
    Response resp(std::format("<meta charset='UTF-8'><h1>Hello, {}!</h1>", name));
    co_return resp.html(std::format("<meta charset='UTF-8'><h1>Hello, {}!</h1>", name));
}

asio::awaitable<Response> get_post_handler(const RequestContext& ctx) {
    auto [post_id, error] = ctx.param<uint32_t>("id");
    if (!error.empty()) co_return failure(error, 404);
    
    json data = {{"post_id", post_id}, {"content", "This is a post."}};
    co_return success(data);
}

asio::awaitable<Response> notify_handler(const RequestContext& ctx) {
    SSEStream* stream = ctx.app.sse_manager.get_stream("notifications");
    if (!stream) co_return not_found("Notifications stream not found");
    
    auto [message, error] = ctx.json_field<std::string>("message");
    if (!error.empty()) co_return bad_request("Error parsing JSON: " + error);
    
    SSEEvent event;
    event.event_type = "notification";
    event.data = json{{"message", message}}.dump();
    co_await stream->broadcast(event);
    co_return success({{"status", "sent"}});
}

asio::awaitable<Response> send_message_handler(const RequestContext& ctx) {
    SSEStream* stream = ctx.app.sse_manager.get_stream("chat_general");
    if (!stream) co_return not_found("Chat room not found");
    
    auto [username, username_error] = ctx.json_field<std::string>("username");
    auto [message, message_error] = ctx.json_field<std::string>("message");
    
    if (!username_error.empty()) co_return bad_request("Username error: " + username_error);
    if (!message_error.empty()) co_return bad_request("Message error: " + message_error);
    
    if (username.empty() || message.empty()) co_return bad_request("Username and message cannot be empty");
    
    bool user_found = false;
    for (const std::shared_ptr<Connection>& c : stream->get_connections()) {
        if (c->get_metadata("username") == username) {
            user_found = true;
            break;
        }
    }
    
    if (!user_found) co_return error(403).json({{"error", "User not found or not connected."}});
    
    SSEEvent message_event;
    message_event.data = json{
        {"type", "message"}, {"user", username}, {"message", message}
    }.dump();
    co_await stream->broadcast(message_event);
    co_return success({{"status", "sent"}});
}

asio::awaitable<Response> view_image_handler(const RequestContext& ctx) {
    auto [filename, error] = ctx.param("image_name");
    if (!error.empty()) {
        co_return bad_request("Invalid filename parameter: " + error);
    }
    
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos || 
        filename.find('\\') != std::string::npos) {
        co_return failure("Access denied",403);
    }
    
    std::string file_path = "uploads/" + filename;
    
    if (!fs::exists(file_path)) {
        co_return not_found("File not found");
    }
    
    co_return serve_file(file_path);
}

asio::awaitable<Response> download_file_handler(const RequestContext& ctx) {
    auto [filename, error] = ctx.param("filename");
    if (!error.empty()) {
        co_return bad_request("Invalid filename parameter: " + error);
    }
    
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos || 
        filename.find('\\') != std::string::npos) {
        co_return failure("Access denied", 403);
    }
    
    std::string file_path = "uploads/" + filename;
    
    if (!fs::exists(file_path)) {
        co_return not_found("File not found");
    }
    
    // Force download with original filename (remove timestamp prefix if present)
    std::string original_name = filename;
    size_t underscore_pos = filename.find('_');
    if (underscore_pos != std::string::npos) {
        original_name = filename.substr(underscore_pos + 1);
    }
    
    co_return download_file(file_path, original_name);
}

int32_t main() {
    try {
        App app(8080);
        app.use(logging_middleware);

        // Chat application endpoints
        app.Get("/", chat_page_handler);
        app.Get("/chat-stream", chat_stream_handler); 
        app.Post("/send", send_message_handler);
        app.Post("/chat/upload", chat_upload_handler); 
        app.Get("view-image/:image_name", view_image_handler);
        app.Get("download-file/:filename", download_file_handler);

        // Private chat endpoints
        app.Post("/request-private-chat", request_private_chat_handler);
        app.Post("/respond-private-chat", respond_private_chat_handler);
        app.Post("/send-private", send_private_message_handler);

        // Other example endpoints
        app.Get("/notifications", notifications_handler);
        app.Post("/notify", notify_handler);
        
        app.Get("/api/info", app_info_handler);
        app.Get("/hello/:name", hello_param_handler);
        app.Get("/posts/:id<uint32>", get_post_handler);

        std::println("Simple responses:");
        std::println("  GET  http://192.168.0.13:8080/api/info           - Simple JSON");
        std::println("  GET  http://192.168.0.13:8080/hello/world        - Parameterized");
        std::println("  GET  http://192.168.0.13:8080/posts/123          - Success wrapper");
        std::println("");
        std::println("URL Decoding example:");
        std::println("  GET  http://192.168.0.13:8080/hello/world%20r+r  - Should return 'Hello, world r+r!'");
        std::println("");
        std::println("SSE endpoints:");
        std::println("  GET  http://192.168.0.13:8080/notifications      - SSE stream");
        std::println("  GET  http://192.168.0.13:8080/                   - Chat Application");
        
        app.run();
    } catch (const std::exception& e) {
        std::println("Fatal error: {}", e.what());
    }
    return 0;
}