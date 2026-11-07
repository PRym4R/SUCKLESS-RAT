# OpenAssist — cross-build from Linux with MinGW-w64 (x86_64-w64-mingw32-g++)
#   apt install mingw-w64
#   make all
CXX      = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wno-unused-value -DNOMINMAX
LIBS     = -static -mwindows -lws2_32 -lsecur32 -lcrypt32 -lcomctl32 -lcomdlg32 -lgdi32

all: panel.exe agent.exe

panel.exe: panel/panel.cpp common/proto.h common/tls.h
	$(CXX) $(CXXFLAGS) panel/panel.cpp -o $@ $(LIBS)

agent.exe: agent/agent.cpp common/proto.h common/tls.h
	$(CXX) $(CXXFLAGS) agent/agent.cpp -o $@ $(LIBS)

clean:
	rm -f panel.exe agent.exe

.PHONY: all clean