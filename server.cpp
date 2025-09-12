/*
 * VPN Tunnel GUI Server - Modernized Edition with Double-Click Support
 * 
 * Dependencies (header-only libraries):
 * - nlohmann/json: https://github.com/nlohmann/json
 *
 * Download these header files:
 * - nlohmann/json.hpp (create nlohmann/ folder and place json.hpp inside)
 * 
 * Build command:
 * g++ -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN server.cpp -o server.exe -luser32 -lgdi32 -lcomctl32 -lws2_32 -static
 * 
 * VPN Port Strategy:
 * - Port 443 (HTTPS): Default port to disguise tunnel traffic
 * - Avoid 8080: Too obvious as alt-HTTP, not VPN-related
 */

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <functional>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstring>

// Modern JSON library (nlohmann/json - header-only)
#include "nlohmann/json.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;
using namespace std::chrono_literals;

// Accept up to 50MB per packet to handle high-resolution screen frames
static constexpr uint32_t MAX_PACKET_SIZE = 50 * 1024 * 1024;

struct ViewerWindowData;

// Window class names
#define WC_MAIN_WINDOW L"VPNTunnelServer"
#define WC_VIEWER_WINDOW L"VPNTunnelViewer"

// Control IDs
#define ID_CLIENT_LIST 1001
#define ID_REFRESH_BTN 1002
#define ID_MODE_TOGGLE 1003

// Custom messages
#define WM_UPDATE_CLIENT_LIST (WM_USER + 1)
#define WM_NEW_SCREEN_DATA (WM_USER + 2)
#define WM_NEW_SCREENSHOT (WM_USER + 3)

// Configuration management - defaults to WireGuard UDP port
struct ServerConfig {
    int port = 443;  // Default port to mimic HTTPS traffic
    std::string log_level = "INFO";
    bool auto_refresh = true;
    int refresh_interval_ms = 5000;
    
    void load(const std::string& filename = "server_config.json") {
        std::ifstream file(filename);
        if (file.is_open()) {
            json config;
            file >> config;
            port = config.value("port", port);
            log_level = config.value("log_level", log_level);
            auto_refresh = config.value("auto_refresh", auto_refresh);
            refresh_interval_ms = config.value("refresh_interval_ms", refresh_interval_ms);
        }
    }
    
    void save(const std::string& filename = "server_config.json") const {
        json config;
        config["port"] = port;
        config["log_level"] = log_level;
        config["auto_refresh"] = auto_refresh;
        config["refresh_interval_ms"] = refresh_interval_ms;
        
        std::ofstream file(filename);
        file << config.dump(2);
    }
};

// Modern logging system
class Logger {
public:
    // Avoid name clashes with Windows headers by prefixing log levels
    enum Level { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR };
    
    static void log(Level level, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                  << level_strings_[level] << ": " << message << std::endl;
    }
    
    static void info(const std::string& msg) { log(LOG_INFO, msg); }
    static void warn(const std::string& msg) { log(LOG_WARN, msg); }
    static void error(const std::string& msg) { log(LOG_ERROR, msg); }
    static void debug(const std::string& msg) { log(LOG_DEBUG, msg); }
    
private:
    static std::mutex log_mutex_;
    static const char* level_strings_[4];
};

std::mutex Logger::log_mutex_;
const char* Logger::level_strings_[4] = {"DEBUG", "INFO", "WARN", "ERROR"};

static bool sendAll(SOCKET s, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int ret = send(s, data + sent, static_cast<int>(std::min<size_t>(len - sent, INT_MAX)), 0);
        if (ret <= 0) {
            Logger::debug("sendAll failed: " + std::to_string(WSAGetLastError()));
            return false;
        }
        sent += static_cast<size_t>(ret);
    }
    return true;
}

static bool recvAll(SOCKET s, char* data, size_t len) {
    size_t received = 0;
    while (received < len) {
        int ret = recv(s, data + received, static_cast<int>(std::min<size_t>(len - received, INT_MAX)), 0);
        if (ret <= 0) {
            Logger::debug("recvAll failed: " + std::to_string(WSAGetLastError()));
            return false;
        }
        received += static_cast<size_t>(ret);
    }
    return true;
}

// Modern client session management
class ClientSession {
public:
    std::string id;
    std::string client_ip;
    SOCKET client_socket = INVALID_SOCKET;
    std::chrono::system_clock::time_point last_seen;
    bool active = false;
    int width = 0, height = 0;
    std::vector<uint8_t> screen_buffer;
    HWND viewer_window = nullptr;
    bool is_connected = false;
    int anchor_x = 0;
    int anchor_y = 0;
    std::vector<uint8_t> screenshot_buffer;
    int screenshot_width = 0;
    int screenshot_height = 0;
    
    // Update screen data with automatic change detection
    bool updateScreen(const std::vector<uint8_t>& new_data, int w, int h) {
        std::lock_guard<std::mutex> lock(screen_mutex_);
        
        bool changed = (width != w || height != h || screen_buffer != new_data);
        if (changed) {
            width = w;
            height = h;
            screen_buffer = new_data;
            last_seen = std::chrono::system_clock::now();
            Logger::debug("Screen updated for " + id + ": " + std::to_string(w) + "x" + std::to_string(h));
        }
        
        return changed;
    }

    bool applyScreenDiff(const std::vector<uint8_t>& diff, int w, int h,
                         int x, int y, int rw, int rh) {
        std::lock_guard<std::mutex> lock(screen_mutex_);

        bool size_changed = (width != w || height != h ||
                             screen_buffer.size() != static_cast<size_t>(w) * h * 3);
        if (size_changed) {
            width = w;
            height = h;
            screen_buffer.assign(static_cast<size_t>(w) * h * 3, 0);
        }

        bool changed = false;
        for (int row = 0; row < rh; ++row) {
            size_t dest_off = (static_cast<size_t>(y + row) * w + x) * 3;
            size_t src_off = static_cast<size_t>(row) * rw * 3;
            uint8_t* dest = screen_buffer.data() + dest_off;
            const uint8_t* src = diff.data() + src_off;
            if (memcmp(dest, src, static_cast<size_t>(rw) * 3) != 0) {
                memcpy(dest, src, static_cast<size_t>(rw) * 3);
                changed = true;
            }
        }

        if (changed) {
            last_seen = std::chrono::system_clock::now();
            Logger::debug("Screen diff applied for " + id +
                          ": region " + std::to_string(x) + "," + std::to_string(y) +
                          " " + std::to_string(rw) + "x" + std::to_string(rh));
        }

        return changed;
    }
    
    // Thread-safe screen data access
    std::tuple<std::vector<uint8_t>, int, int> getScreenData() const {
        std::lock_guard<std::mutex> lock(screen_mutex_);
        return {screen_buffer, width, height};
    }

    void setScreenshot(const std::vector<uint8_t>& data, int w, int h) {
        std::lock_guard<std::mutex> lock(screenshot_mutex_);
        screenshot_buffer = data;
        screenshot_width = w;
        screenshot_height = h;
    }

    std::tuple<std::vector<uint8_t>, int, int> getScreenshot() const {
        std::lock_guard<std::mutex> lock(screenshot_mutex_);
        return {screenshot_buffer, screenshot_width, screenshot_height};
    }

private:
    mutable std::mutex screen_mutex_;
    mutable std::mutex screenshot_mutex_;
};

// Modern client manager with smart pointers
class ClientManager {
public:
    using ClientPtr = std::shared_ptr<ClientSession>;
    
    ClientPtr createSession(const std::string& client_ip) {
        std::string session_id = generateSessionId();
        auto client = std::make_shared<ClientSession>();
        client->id = session_id;
        client->client_ip = client_ip;
        client->last_seen = std::chrono::system_clock::now();
        client->active = true;
        
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_[session_id] = client;
        
        Logger::info("New session created: " + session_id + " from " + client_ip);
        return client;
    }
    
    ClientPtr getSession(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = clients_.find(session_id);
        return (it != clients_.end()) ? it->second : nullptr;
    }
    
    std::vector<ClientPtr> getAllSessions() {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        std::vector<ClientPtr> result;
        for (const auto& pair : clients_) {
            if (pair.second->active) {
                result.push_back(pair.second);
            }
        }
        return result;
    }
    
    void removeInactiveSessions(std::chrono::seconds timeout = 300s) {
        auto now = std::chrono::system_clock::now();
        std::lock_guard<std::mutex> lock(clients_mutex_);
        
        auto it = clients_.begin();
        while (it != clients_.end()) {
            if (now - it->second->last_seen > timeout) {
                Logger::info("Removing inactive session: " + it->first);
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
private:
    std::unordered_map<std::string, ClientPtr> clients_;
    std::mutex clients_mutex_;
    
    std::string generateSessionId() {
        static const char chars[] = "0123456789abcdef";
        std::string result(16, '0');
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        for (char& c : result) {
            c = chars[dis(gen)];
        }
        
        return result;
    }
};

static bool SaveBMP(const std::string& filename, const std::vector<uint8_t>& data, int width, int height) {
    BITMAPFILEHEADER bfh{};
    BITMAPINFOHEADER bih{};
    int rowSize = width * 3;
    int padding = (4 - (rowSize % 4)) % 4;
    int dataSize = (rowSize + padding) * height;

    bfh.bfType = 0x4D42;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + dataSize;

    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = width;
    bih.biHeight = -height;
    bih.biPlanes = 1;
    bih.biBitCount = 24;
    bih.biCompression = BI_RGB;
    bih.biSizeImage = dataSize;

    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(&bfh), sizeof(bfh));
    file.write(reinterpret_cast<const char*>(&bih), sizeof(bih));

    for (int y = 0; y < height; ++y) {
        file.write(reinterpret_cast<const char*>(data.data() + y * width * 3), rowSize);
        if (padding) {
            uint8_t pad[3] = {0,0,0};
            file.write(reinterpret_cast<const char*>(pad), padding);
        }
    }
    return true;
}

static void SaveClientRegionScreenshot(ClientSession& client) {
    auto [screen, width, height] = client.getScreenData();
    int x = std::clamp(client.anchor_x, 0, width > 0 ? width - 1 : 0);
    int y = std::clamp(client.anchor_y, 0, height > 0 ? height - 1 : 0);
    if (width == 0 || height == 0 || x >= width || y >= height) return;
    int w = width - x;
    int h = height - y;
    std::vector<uint8_t> region(w * h * 3);
    for (int row = 0; row < h; ++row) {
        memcpy(region.data() + row * w * 3,
               screen.data() + ((y + row) * width + x) * 3,
               w * 3);
    }
    std::ostringstream name;
    name << "screenshot_" << client.id << ".bmp";
    if (SaveBMP(name.str(), region, w, h)) {
        Logger::info("Saved screenshot for session " + client.id);
    }
    client.setScreenshot(region, w, h);
    if (client.viewer_window && IsWindow(client.viewer_window)) {
        PostMessage(client.viewer_window, WM_NEW_SCREENSHOT, 0, 0);
    }
}

static void ToggleSplitScreen(ClientSession& client);

struct WireGuardHeader {
    BYTE type;
    BYTE reserved[3];
    DWORD sender_index;
    ULONGLONG counter;
    BYTE nonce[12];

    WireGuardHeader() {
        type = 0x04;
        memset(reserved, 0, 3);
        sender_index = GetTickCount();
        counter = GetTickCount64();
        for (int i = 0; i < 12; i++) {
            nonce[i] = rand() % 256;
        }
    }
};

struct WireGuardPacket {
    WireGuardHeader header;
    std::vector<BYTE> encrypted_payload;
    BYTE auth_tag[16];

    WireGuardPacket(const std::vector<BYTE>& payload) {
        encrypted_payload = payload;
        for (int i = 0; i < 16; i++) {
            auth_tag[i] = rand() % 256;
        }
    }

    std::vector<BYTE> serialize() const {
        std::vector<BYTE> packet;
        packet.resize(sizeof(WireGuardHeader));
        memcpy(packet.data(), &header, sizeof(WireGuardHeader));
        packet.insert(packet.end(), encrypted_payload.begin(), encrypted_payload.end());
        packet.insert(packet.end(), auth_tag, auth_tag + 16);
        return packet;
    }

    static WireGuardPacket deserialize(const std::vector<BYTE>& data) {
        WireGuardPacket packet({});
        if (data.size() >= sizeof(WireGuardHeader) + 16) {
            memcpy(&packet.header, data.data(), sizeof(WireGuardHeader));
            size_t payload_size = data.size() - sizeof(WireGuardHeader) - 16;
            packet.encrypted_payload.assign(
                data.begin() + sizeof(WireGuardHeader),
                data.begin() + sizeof(WireGuardHeader) + payload_size
            );
            memcpy(packet.auth_tag, data.data() + data.size() - 16, 16);
        }
        return packet;
    }
};

class TunnelProtocol {
public:
    static std::vector<BYTE> createTunnelPayload(const std::string& type, const std::string& data) {
        std::stringstream payload;
        payload << type << ":" << data;
        std::string payload_str = payload.str();
        std::vector<BYTE> result(payload_str.begin(), payload_str.end());
        while (result.size() % 16 != 0) {
            result.push_back(0x00);
        }
        return result;
    }

    static std::pair<std::string, std::string> extractTunnelPayload(const std::vector<BYTE>& payload) {
        std::string data(payload.begin(), payload.end());
        size_t colon_pos = data.find(':');
        if (colon_pos != std::string::npos) {
            std::string type = data.substr(0, colon_pos);
            std::string value = data.substr(colon_pos + 1);
            value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
                return ch != '\0';
            }).base(), value.end());
            return {type, value};
        }
        return {"", ""};
    }
};

// CRITICAL: Low-level client compatibility layer
// This ensures clients receive EXACTLY the same data format
class ClientProtocolHandler {
public:
    // Generate response that matches client's expectations exactly
    static std::string createAuthResponse(const std::string& session_id) {
        // Must match client's expected JSON format exactly
        json response;
        response["session"] = session_id;
        response["status"] = "authenticated";
        return response.dump();
    }
    
    static std::string createControlResponse(const std::string& input_command) {
        if (input_command.empty()) {
            return "{}"; // Empty response when no commands
        }
        
        // Encode using same algorithm as client expects
        std::string encoded = encodeForClient(input_command);
        
        json response;
        response["input"] = encoded;
        return response.dump();
    }
    
    // CRITICAL: This must match the client's decoder exactly
    static std::string encodeForClient(const std::string& input) {
        static const char chars[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/";
        
        std::string result;
        int val = 0, valb = -6;
        
        for (unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        while (result.size() % 4) {
            result.push_back('=');
        }
        
        return result;
    }
    
    // CRITICAL: This must match the client's encoder exactly  
    static std::vector<uint8_t> decodeFromClient(const std::string& input) {
        std::vector<int> T(256, -1);
        const char chars[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/";
        for (int i = 0; i < 64; i++) T[chars[i]] = i;
        
        std::vector<uint8_t> result;
        int val = 0, valb = -8;
        
        for (unsigned char c : input) {
            // Stop decoding at padding or unexpected characters to avoid
            // interpreting trailing garbage as valid data. This mirrors the
            // client's decoder behaviour and prevents spurious bytes that can
            // corrupt frame sizes.
            if (c == '=' || T[c] == -1) {
                break;
            }

            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                result.push_back((val >> valb) & 0xFF);
                valb -= 8;
            }
        }
        
        return result;
    }
    
    // CRITICAL: RLE decompression must match client exactly
    static std::vector<uint8_t> decompressRLE(const std::vector<uint8_t>& compressed) {
        std::vector<uint8_t> result;
        
        for (size_t i = 0; i < compressed.size(); ) {
            if (compressed[i] == 0xFF) {
                if (i + 2 < compressed.size() && compressed[i + 1] != 0) {
                    uint8_t count = compressed[i + 1];
                    uint8_t value = compressed[i + 2];
                    for (int j = 0; j < count; j++) {
                        result.push_back(value);
                    }
                    i += 3;
                } else {
                    // Treat missing or zero-count run as literal 0xFF
                    result.push_back(0xFF);
                    i++;
                }
            } else {
                result.push_back(compressed[i]);
                i++;
            }
        }
        
        return result;
    }
    
    // Extract tunnel data (must match client wrapper format)
    static std::string extractTunnelData(const std::string& wrapped) {
        if (wrapped.length() < 12) return "";
        
        size_t start = 12; // Skip protocol header + session fragment
        size_t end = wrapped.find("\xFF\xFF"); // Find footer
        if (end == std::string::npos) end = wrapped.length();
        
        return wrapped.substr(start, end - start);
    }
};

// Global instances
ServerConfig g_config;
std::unique_ptr<ClientManager> g_clientManager;
extern HWND g_hMainWnd;

class VPNTunnelServer {
public:
    VPNTunnelServer(int port) : port_(port) {
        g_clientManager = std::make_unique<ClientManager>();
        Logger::info("VPN Tunnel TCP server initialized on port " + std::to_string(port));
    }

    void start();
    void stop();

private:
    void serverLoop();
    void handleClient(SOCKET client_socket);

    int port_;
    SOCKET listen_socket_ = INVALID_SOCKET;
    std::thread server_thread_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{true};
};

void VPNTunnelServer::start() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        Logger::error("WSAStartup failed");
        return;
    }

    server_thread_ = std::thread([this]() { serverLoop(); });
    cleanup_thread_ = std::thread([this]() {
        while (running_) {
            std::this_thread::sleep_for(30s);
            g_clientManager->removeInactiveSessions();
        }
    });
}

void VPNTunnelServer::stop() {
    running_ = false;
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    WSACleanup();
}

void VPNTunnelServer::serverLoop() {
    listen_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket_ == INVALID_SOCKET) {
        Logger::error("Failed to create TCP socket");
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_);
    if (bind(listen_socket_, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        Logger::error("Failed to bind TCP socket");
        return;
    }

    if (listen(listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Failed to listen on TCP socket");
        return;
    }

    Logger::info("TCP server listening on port " + std::to_string(port_));

    while (running_) {
        sockaddr_in client_addr{};
        int addrlen = sizeof(client_addr);
        SOCKET client_socket = accept(listen_socket_, (sockaddr*)&client_addr, &addrlen);
        if (client_socket == INVALID_SOCKET) continue;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        Logger::debug("Accepted connection from " + std::string(ip));
        std::thread(&VPNTunnelServer::handleClient, this, client_socket).detach();
    }
}

void VPNTunnelServer::handleClient(SOCKET client_socket) {
    sockaddr_in addr{};
    int addrlen = sizeof(addr);
    getpeername(client_socket, (sockaddr*)&addr, &addrlen);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    Logger::debug("Client handler started for " + std::string(ip));
    std::shared_ptr<ClientSession> client;

    while (running_) {
        uint32_t len = 0;
        if (!recvAll(client_socket, reinterpret_cast<char*>(&len), sizeof(len))) {
            Logger::debug("Failed to receive length from " + std::string(ip));
            break;
        }
        len = ntohl(len);
        Logger::debug("Incoming packet length: " + std::to_string(len));
        if (len == 0 || len > MAX_PACKET_SIZE) {
            Logger::debug("Invalid packet length from " + std::string(ip));
            break;
        }
        std::vector<BYTE> data(len);
        if (!recvAll(client_socket, reinterpret_cast<char*>(data.data()), len)) {
            Logger::debug("Failed to receive payload from " + std::string(ip));
            break;
        }

        WireGuardPacket packet = WireGuardPacket::deserialize(data);
        auto [type, payload] = TunnelProtocol::extractTunnelPayload(packet.encrypted_payload);
        Logger::debug("Packet type from " + std::string(ip) + ": " + type);

        if (type == "handshake") {
            Logger::debug("Processing handshake from " + std::string(ip));
            client = g_clientManager->createSession(ip);
            client->client_socket = client_socket;
            auto payloadOut = TunnelProtocol::createTunnelPayload("session", client->id);
            WireGuardPacket pkt(payloadOut);
            auto d = pkt.serialize();
            uint32_t out_len = htonl(static_cast<uint32_t>(d.size()));
            if (!sendAll(client_socket, reinterpret_cast<const char*>(&out_len), sizeof(out_len))) {
                Logger::debug("Failed to send handshake length to " + std::string(ip));
                break;
            }
            if (!sendAll(client_socket, reinterpret_cast<const char*>(d.data()), d.size())) {
                Logger::debug("Failed to send handshake payload to " + std::string(ip));
                break;
            }
            Logger::info("Handshake from " + std::string(ip) + " -> session " + client->id);
            if (g_hMainWnd) PostMessage(g_hMainWnd, WM_UPDATE_CLIENT_LIST, 0, 0);
        } else if (type == "screen") {
            size_t p1 = payload.find('|');
            size_t p2 = payload.find('|', p1 + 1);
            size_t p3 = payload.find('|', p2 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) continue;

            std::string session_id = payload.substr(0, p1);
            std::string dim = payload.substr(p1 + 1, p2 - p1 - 1);
            std::string rect = payload.substr(p2 + 1, p3 - p2 - 1);
            std::string encoded = payload.substr(p3 + 1);
            Logger::debug("Processing screen packet for session " + session_id);

            int width = 0, height = 0;
            if (sscanf(dim.c_str(), "%dx%d", &width, &height) != 2 || width <= 0 || height <= 0) {
                Logger::error("Invalid frame dimensions for session " + session_id + ": " + dim);
                continue;
            }

            int x = 0, y = 0, rw = 0, rh = 0;
            if (sscanf(rect.c_str(), "%d,%d,%d,%d", &x, &y, &rw, &rh) != 4 || rw <= 0 || rh <= 0) {
                Logger::error("Invalid region for session " + session_id + ": " + rect);
                continue;
            }

            auto c = g_clientManager->getSession(session_id);
            if (!c) continue;
            c->client_socket = client_socket;

            auto decoded = ClientProtocolHandler::decodeFromClient(encoded);
            auto region_data = ClientProtocolHandler::decompressRLE(decoded);
            size_t expected_size = static_cast<size_t>(rw) * static_cast<size_t>(rh) * 3;
            if (region_data.size() != expected_size) {
                Logger::error("Invalid diff size for session " + session_id +
                              ": expected " + std::to_string(expected_size) +
                              " bytes, got " + std::to_string(region_data.size()));
                c->updateScreen({}, width, height);
                auto diag_payload = TunnelProtocol::createTunnelPayload("error", "invalid_frame");
                WireGuardPacket diag_pkt(diag_payload);
                auto diag_out = diag_pkt.serialize();
                uint32_t diag_len = htonl(static_cast<uint32_t>(diag_out.size()));
                sendAll(client_socket, reinterpret_cast<const char*>(&diag_len), sizeof(diag_len));
                sendAll(client_socket, reinterpret_cast<const char*>(diag_out.data()), diag_out.size());
                continue;
            }

            bool changed = c->applyScreenDiff(region_data, width, height, x, y, rw, rh);
            if (changed) {
                if (c->viewer_window && IsWindow(c->viewer_window)) {
                    PostMessage(c->viewer_window, WM_NEW_SCREEN_DATA, 0, 0);
                }
                if (g_hMainWnd) {
                    PostMessage(g_hMainWnd, WM_UPDATE_CLIENT_LIST, 0, 0);
                }
            }
            Logger::debug("Updated screen for session " + session_id +
                          " (" + std::to_string(width) + "x" + std::to_string(height) +
                          ") region " + std::to_string(x) + "," + std::to_string(y) +
                          " " + std::to_string(rw) + "x" + std::to_string(rh));

        } else if (type == "event") {
            size_t p = payload.find('|');
            if (p == std::string::npos) continue;
            std::string session_id = payload.substr(0, p);
            std::string evt = payload.substr(p + 1);
            auto c = g_clientManager->getSession(session_id);
            if (!c) continue;
            if (evt.rfind("middle:", 0) == 0) {
                int x = 0, y = 0;
                if (sscanf(evt.c_str() + 7, "%d,%d", &x, &y) == 2) {
                    c->anchor_x = x;
                    c->anchor_y = y;
                    Logger::info("Anchor updated for session " + session_id +
                                 ": " + std::to_string(x) + "," + std::to_string(y));
                }
            } else if (evt == "right") {
                SaveClientRegionScreenshot(*c);
            } else if (evt == "long_middle") {
                ToggleSplitScreen(*c);
            }
        } else {
            Logger::debug("Unknown packet type from " + std::string(ip) + ": " + type);
        }
    }

    if (client) {
        client->active = false;
    }

    Logger::debug("Closing connection for " + std::string(ip));
    closesocket(client_socket);
}

// Global GUI variables  
HINSTANCE g_hInstance = nullptr;
HWND g_hMainWnd = nullptr;
HWND g_hClientList = nullptr;
std::unique_ptr<VPNTunnelServer> g_vpnServer;

// Remote desktop viewer window data (unchanged - GUI only)
struct ViewerWindowData {
    std::string session_id;
    HBITMAP screen_bitmap;
    HBITMAP screenshot_bitmap;
    bool split_mode;
    int remote_width;
    int remote_height;
    RECT draw_rect; // area where remote screen is rendered
};

static void ToggleSplitScreen(ClientSession& client) {
    if (client.viewer_window && IsWindow(client.viewer_window)) {
        ViewerWindowData* data = (ViewerWindowData*)GetWindowLongPtr(client.viewer_window, GWLP_USERDATA);
        if (data) {
            data->split_mode = !data->split_mode;
            if (!data->split_mode) {
                int screenW = GetSystemMetrics(SM_CXSCREEN);
                int screenH = GetSystemMetrics(SM_CYSCREEN);
                SetWindowPos(client.viewer_window, HWND_TOPMOST, 0, 0, screenW, screenH, SWP_SHOWWINDOW);
            }
            InvalidateRect(client.viewer_window, nullptr, TRUE);
        }
    }
}

// Modern GUI helper functions
void UpdateClientList() {
    if (!g_hClientList) return;
    
    ListView_DeleteAllItems(g_hClientList);
    
    auto clients = g_clientManager->getAllSessions();
    int index = 0;
    
    for (const auto& client : clients) {
        LVITEMA item = {0};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = index++;
        item.iSubItem = 0;
        item.pszText = const_cast<char*>(client->client_ip.c_str());
        item.lParam = reinterpret_cast<LPARAM>(client.get());
        
        int itemIndex = ListView_InsertItem(g_hClientList, &item);
        
        ListView_SetItemText(g_hClientList, itemIndex, 1, const_cast<LPSTR>(client->id.c_str()));
        
        auto [screen_data, width, height] = client->getScreenData();
        char resolution[32];
        sprintf_s(resolution, sizeof(resolution), "%dx%d", width, height);
        ListView_SetItemText(g_hClientList, itemIndex, 2, resolution);
        
        ListView_SetItemText(g_hClientList, itemIndex, 3,
                             client->is_connected ? (LPSTR)"Connected" : (LPSTR)"Idle");
    }
    
    Logger::debug("Client list updated with " + std::to_string(clients.size()) + " clients");
}

HBITMAP CreateScreenBitmap(const std::vector<uint8_t>& screen_data, int width, int height) {
    if (screen_data.empty() || width == 0 || height == 0) return nullptr;
    
    HDC hdc = GetDC(nullptr);
    
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    void* pBits;
    HBITMAP hBitmap = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &pBits, nullptr, 0);

    if (hBitmap && pBits) {
        int stride = ((width * 3 + 3) & ~3);
        uint8_t* dst = static_cast<uint8_t*>(pBits);
        const uint8_t* src = screen_data.data();

        // Clear the entire buffer to avoid artifacts in the padding bytes
        memset(dst, 0, static_cast<size_t>(stride) * static_cast<size_t>(height));

        // Copy each row's pixel data, leaving zeroed padding at the end of each row
        for (int y = 0; y < height; ++y) {
            memcpy(dst + static_cast<size_t>(y) * stride,
                   src + static_cast<size_t>(y) * width * 3,
                   static_cast<size_t>(width) * 3);
        }
    }
    
    ReleaseDC(nullptr, hdc);
    return hBitmap;
}

void OpenViewerWindow(const std::string& session_id) {
    auto client = g_clientManager->getSession(session_id);
    if (!client) {
        Logger::warn("Attempted to open viewer for non-existent session: " + session_id);
        return;
    }
    
    // Check if window already exists
    if (client->viewer_window && IsWindow(client->viewer_window)) {
        SetForegroundWindow(client->viewer_window);
        return;
    }
    
    // Create new viewer window data
    auto data = std::make_unique<ViewerWindowData>();
    data->session_id = session_id;
    data->screen_bitmap = nullptr;
    data->screenshot_bitmap = nullptr;
    data->split_mode = false;

    auto [screen_data, width, height] = client->getScreenData();
    data->remote_width = width;
    data->remote_height = height;
    SetRect(&data->draw_rect, 0, 0, 0, 0);
    
    char title[256];
    sprintf_s(title, sizeof(title), "Remote Desktop - %s (%s)", 
             client->client_ip.c_str(), session_id.c_str());
    
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    HWND hViewer = CreateWindowExA(
        WS_EX_TOPMOST,
        "VPNTunnelViewer",
        title,
        WS_POPUP,
        0, 0, screenW, screenH,
        nullptr, nullptr, g_hInstance, data.release() // Transfer ownership
    );

    if (hViewer) {
        client->viewer_window = hViewer;
        client->is_connected = true;
        SetWindowPos(hViewer, HWND_TOPMOST, 0, 0, screenW, screenH, SWP_SHOWWINDOW);
        UpdateWindow(hViewer);

        // Update screen if we already have data
        if (!screen_data.empty()) {
            ViewerWindowData* window_data = (ViewerWindowData*)GetWindowLongPtr(hViewer, GWLP_USERDATA);
            if (window_data) {
                window_data->screen_bitmap = CreateScreenBitmap(screen_data, width, height);
                InvalidateRect(hViewer, nullptr, TRUE);
            }
        }
        
        Logger::info("Opened viewer window for session " + session_id);
    }
}

// Remote desktop viewer window procedure (modernized)
LRESULT CALLBACK ViewerWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ViewerWindowData* data = (ViewerWindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    switch (uMsg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        data = (ViewerWindowData*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)data);
        
        // Create mode toggle button
        CreateWindowW(L"BUTTON", L"⚏", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     0, 0, 30, 25, hwnd, (HMENU)ID_MODE_TOGGLE, g_hInstance, nullptr);
        
        Logger::debug("Viewer window created for session " + data->session_id);
        return 0;
    }
    
    case WM_SIZE: {
        // Reposition mode toggle button
        HWND hToggle = GetDlgItem(hwnd, ID_MODE_TOGGLE);
        if (hToggle) {
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            SetWindowPos(hToggle, HWND_TOP, clientRect.right - 35, 5, 30, 25, SWP_NOZORDER);
        }
        
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    
    case WM_COMMAND: {
        if (LOWORD(wParam) == ID_MODE_TOGGLE && data) {
            data->split_mode = !data->split_mode;
            InvalidateRect(hwnd, nullptr, TRUE);
            Logger::debug("Toggled split mode for session " + data->session_id + ": " + 
                         (data->split_mode ? "ON" : "OFF"));
        }
        return 0;
    }
    
    case WM_NEW_SCREEN_DATA: {
        if (data) {
            auto client = g_clientManager->getSession(data->session_id);
            if (client) {
                auto [screen_data, width, height] = client->getScreenData();
                
                if (data->screen_bitmap) {
                    DeleteObject(data->screen_bitmap);
                }
                
                data->screen_bitmap = CreateScreenBitmap(screen_data, width, height);
                data->remote_width = width;
                data->remote_height = height;
                
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        }
        return 0;
    }

    case WM_NEW_SCREENSHOT: {
        if (data) {
            auto client = g_clientManager->getSession(data->session_id);
            if (client) {
                auto [shot_data, w, h] = client->getScreenshot();
                if (data->screenshot_bitmap) {
                    DeleteObject(data->screenshot_bitmap);
                    data->screenshot_bitmap = nullptr;
                }
                data->screenshot_bitmap = CreateScreenBitmap(shot_data, w, h);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        }
        return 0;
    }

    case WM_ERASEBKGND:
        // Prevent flicker by avoiding default background erasing
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT clientRect;
        GetClientRect(hwnd, &clientRect);

        // Double buffering to eliminate flashing when redrawing
        HDC hdcBuffer = CreateCompatibleDC(hdc);
        HBITMAP hbmBuffer = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        HBITMAP hbmOldBuffer = (HBITMAP)SelectObject(hdcBuffer, hbmBuffer);

        if (data && data->screen_bitmap) {
            HDC hdcMem = CreateCompatibleDC(hdcBuffer);
            HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, data->screen_bitmap);
            HDC hdcShot = nullptr;
            HBITMAP hOldShot = nullptr;
            if (data->screenshot_bitmap) {
                hdcShot = CreateCompatibleDC(hdcBuffer);
                hOldShot = (HBITMAP)SelectObject(hdcShot, data->screenshot_bitmap);
            }

            BITMAP bm;
            GetObject(data->screen_bitmap, sizeof(bm), &bm);

            if (data->split_mode) {
                int barHeight = clientRect.bottom * 15 / 100;
                RECT innerRect = {0, barHeight, clientRect.right, clientRect.bottom - barHeight};

                // fill entire background black (top/bottom bars)
                FillRect(hdcBuffer, &clientRect, (HBRUSH)GetStockObject(BLACK_BRUSH));

                int halfWidth = (innerRect.right - innerRect.left) / 2;
                RECT leftRect = {0, innerRect.top, halfWidth, innerRect.bottom};
                if (hdcShot) {
                    BITMAP sbm;
                    GetObject(data->screenshot_bitmap, sizeof(sbm), &sbm);
                    StretchBlt(hdcBuffer, leftRect.left, leftRect.top,
                              leftRect.right - leftRect.left,
                              leftRect.bottom - leftRect.top,
                              hdcShot, 0, 0, sbm.bmWidth, sbm.bmHeight, SRCCOPY);
                } else {
                    FillRect(hdcBuffer, &leftRect, (HBRUSH)(COLOR_BTNFACE + 1));
                    DrawTextA(hdcBuffer, "Tool Panel\n(Coming Soon)", -1, &leftRect,
                             DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                }

                RECT rightArea = {halfWidth, innerRect.top, innerRect.right, innerRect.bottom};

                double remoteAspect = static_cast<double>(bm.bmWidth) / bm.bmHeight;
                double areaAspect = static_cast<double>(rightArea.right - rightArea.left) /
                                    (rightArea.bottom - rightArea.top);
                int destWidth = rightArea.right - rightArea.left;
                int destHeight = rightArea.bottom - rightArea.top;
                int destX = rightArea.left;
                int destY = rightArea.top;

                if (areaAspect > remoteAspect) {
                    destWidth = static_cast<int>((rightArea.bottom - rightArea.top) * remoteAspect);
                    destX = rightArea.left + ( (rightArea.right - rightArea.left - destWidth) / 2 );
                } else {
                    destHeight = static_cast<int>((rightArea.right - rightArea.left) / remoteAspect);
                    destY = rightArea.top + ( (rightArea.bottom - rightArea.top - destHeight) / 2 );
                }

                data->draw_rect = {destX, destY, destX + destWidth, destY + destHeight};

                StretchBlt(hdcBuffer, destX, destY, destWidth, destHeight,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            } else {
                double remoteAspect = static_cast<double>(bm.bmWidth) / bm.bmHeight;
                double windowAspect = static_cast<double>(clientRect.right) / clientRect.bottom;
                int destWidth = clientRect.right;
                int destHeight = clientRect.bottom;
                int destX = 0;
                int destY = 0;

                if (windowAspect > remoteAspect) {
                    destWidth = static_cast<int>(clientRect.bottom * remoteAspect);
                    destX = (clientRect.right - destWidth) / 2;
                } else {
                    destHeight = static_cast<int>(clientRect.right / remoteAspect);
                    destY = (clientRect.bottom - destHeight) / 2;
                }

                data->draw_rect = {destX, destY, destX + destWidth, destY + destHeight};

                FillRect(hdcBuffer, &clientRect, (HBRUSH)GetStockObject(BLACK_BRUSH));
                StretchBlt(hdcBuffer, destX, destY, destWidth, destHeight,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            }

            SelectObject(hdcMem, hOldBitmap);
            DeleteDC(hdcMem);
            if (hdcShot) {
                SelectObject(hdcShot, hOldShot);
                DeleteDC(hdcShot);
            }
        } else {
            FillRect(hdcBuffer, &clientRect, (HBRUSH)(COLOR_WINDOW + 1));

            std::string status = data ?
                "Connecting to " + data->session_id + "..." :
                "No connection";

            DrawTextA(hdcBuffer, status.c_str(), -1, &clientRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }

        // Blit the offscreen buffer to the window in one operation
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, hdcBuffer, 0, 0, SRCCOPY);

        // Cleanup buffer objects
        SelectObject(hdcBuffer, hbmOldBuffer);
        DeleteObject(hbmBuffer);
        DeleteDC(hdcBuffer);

        EndPaint(hwnd, &ps);
        return 0;
    }
    
    case WM_LBUTTONDOWN:
        return 0;

    case WM_RBUTTONDOWN:
        return 0;

    case WM_CHAR:
        return 0;
    
    case WM_CLOSE: {
        if (data) {
            // Mark client as disconnected
            auto client = g_clientManager->getSession(data->session_id);
            if (client) {
                client->viewer_window = nullptr;
                client->is_connected = false;
                Logger::info("Viewer window closed for session " + data->session_id);
            }
            
            if (data->screen_bitmap) {
                DeleteObject(data->screen_bitmap);
            }
            if (data->screenshot_bitmap) {
                DeleteObject(data->screenshot_bitmap);
            }
            delete data;
        }
        DestroyWindow(hwnd);
        return 0;
    }
    
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Main window procedure (modernized)
LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Initialize common controls
        InitCommonControls();
        
        // Create refresh button
        CreateWindowW(L"BUTTON", L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     10, 10, 80, 30, hwnd, (HMENU)ID_REFRESH_BTN, g_hInstance, nullptr);
        
        // Create client list view (ANSI variant to avoid UNICODE dependency)
        g_hClientList = CreateWindowA(WC_LISTVIEWA, "",
                                     WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                                     10, 50, 600, 300, hwnd, (HMENU)ID_CLIENT_LIST, g_hInstance, nullptr);
        
        // Set up list view columns
        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        col.pszText = (LPSTR)"Client IP";
        col.cx = 120;
        col.iSubItem = 0;
        ListView_InsertColumn(g_hClientList, 0, &col);

        col.pszText = (LPSTR)"Session ID";
        col.cx = 140;
        col.iSubItem = 1;
        ListView_InsertColumn(g_hClientList, 1, &col);

        col.pszText = (LPSTR)"Resolution";
        col.cx = 100;
        col.iSubItem = 2;
        ListView_InsertColumn(g_hClientList, 2, &col);

        col.pszText = (LPSTR)"Status";
        col.cx = 80;
        col.iSubItem = 3;
        ListView_InsertColumn(g_hClientList, 3, &col);
        
        // Enable full row select
        ListView_SetExtendedListViewStyle(g_hClientList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        
        // Set initial window title
        SetWindowTextA(hwnd, "VPN Tunnel Server - Initializing...");
        
        // Start auto-refresh timer if enabled
        if (g_config.auto_refresh) {
            SetTimer(hwnd, 1, g_config.refresh_interval_ms, nullptr);
        }
        
        return 0;
    }
    
    case WM_SIZE: {
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        
        // Resize list view
        if (g_hClientList) {
            SetWindowPos(g_hClientList, nullptr, 10, 50, 
                        clientRect.right - 20, clientRect.bottom - 60, SWP_NOZORDER);
        }
        return 0;
    }
    
    case WM_TIMER: {
        if (wParam == 1) { // Auto-refresh timer
            UpdateClientList();
        }
        return 0;
    }
    
    case WM_COMMAND: {
        if (LOWORD(wParam) == ID_REFRESH_BTN) {
            UpdateClientList();
            Logger::info("Manual client list refresh requested");
        }
        return 0;
    }
    
    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == ID_CLIENT_LIST && pnmh->code == NM_DBLCLK) {
            int selected = ListView_GetNextItem(g_hClientList, -1, LVNI_SELECTED);
            if (selected != -1) {
                char session_id[64];
                ListView_GetItemText(g_hClientList, selected, 1, session_id, sizeof(session_id));
                OpenViewerWindow(std::string(session_id));
            }
        }
        return 0;
    }
    
    case WM_UPDATE_CLIENT_LIST: {
        UpdateClientList();
        return 0;
    }
    
    case WM_DESTROY:
        if (g_vpnServer) {
            g_vpnServer->stop();
        }
        PostQuitMessage(0);
        return 0;
        
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// NEW: Double-click functionality - Auto-start on configured port
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInstance = hInstance;

    try {
        // Make the GUI DPI aware so high-resolution remote desktops are handled
        // using their actual pixel dimensions instead of being limited to
        // 1920x1080 by Windows DPI virtualization.
        SetProcessDPIAware();
        // Load configuration
        g_config.load();
        
        // DOUBLE-CLICK MODE: If arguments provided, treat as port override
        if (strlen(lpCmdLine) != 0) {
            int port = atoi(lpCmdLine);
            if (port > 0 && port < 65536) {
                g_config.port = port;
                Logger::info("Port override from command line: " + std::to_string(port));
            } else {
                Logger::warn("Invalid port specified, using default " + std::to_string(g_config.port));
            }
        } else {
            Logger::info("Double-click mode: Auto-starting on port " + std::to_string(g_config.port));
        }
        
        // Register main window class
        WNDCLASSW wc = {0};
        wc.lpfnWndProc = MainWindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = WC_MAIN_WINDOW;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        
        if (!RegisterClassW(&wc)) {
            Logger::error("Failed to register main window class");
            return 1;
        }
        
        // Register viewer window class
        WNDCLASSW vc = {0};
        vc.lpfnWndProc = ViewerWindowProc;
        vc.hInstance = hInstance;
        vc.lpszClassName = WC_VIEWER_WINDOW;
        vc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        vc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        vc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        
        if (!RegisterClassW(&vc)) {
            Logger::error("Failed to register viewer window class");
            return 1;
        }
        
        // Create main window with port info in title
        char windowTitle[256];
        sprintf_s(windowTitle, sizeof(windowTitle), "VPN Tunnel Server - Port %d", g_config.port);
        
        g_hMainWnd = CreateWindowA(
            "VPNTunnelServer",
            windowTitle,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 640, 400,
            nullptr, nullptr, hInstance, nullptr
        );
        
        if (!g_hMainWnd) {
            Logger::error("Failed to create main window");
            return 1;
        }
        
        ShowWindow(g_hMainWnd, nCmdShow);
        UpdateWindow(g_hMainWnd);
        
        // Start VPN tunnel server
        g_vpnServer = std::make_unique<VPNTunnelServer>(g_config.port);
        g_vpnServer->start();
        
        // DOUBLE-CLICK MODE: Show startup notification
        if (strlen(lpCmdLine) == 0) {
            char startupMsg[512];
            sprintf_s(startupMsg, sizeof(startupMsg), 
                     "VPN Tunnel Server started successfully!\n\n"
                     "Listening on port: %d (VPN Management Port)\n"
                     "Ready to accept client connections.\n\n"
                     "Instructions:\n"
                     "• Clients will appear in the list below\n"
                     "• Double-click any client to view their desktop\n"
                     "• Use the ⚏ button to toggle split-screen mode",
                     g_config.port);
            
            MessageBoxA(g_hMainWnd, startupMsg, "VPN Server Ready", MB_OK | MB_ICONINFORMATION);
        }
        
        Logger::info("VPN Tunnel Server GUI started successfully on port " + std::to_string(g_config.port));
        
        // Message loop
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        // Save configuration on exit
        g_config.save();
        Logger::info("Configuration saved on exit");
        
        return 0;
        
    } catch (const std::exception& e) {
        Logger::error("Fatal error: " + std::string(e.what()));
        MessageBoxA(nullptr, e.what(), "VPN Tunnel Server Error", MB_OK | MB_ICONERROR);
        return 1;
    }
}