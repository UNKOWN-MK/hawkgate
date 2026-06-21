CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -I src -I ../kernel
LDFLAGS  = -lbpf

BUILD_DIR = build
TARGET    = $(BUILD_DIR)/hawkgated
READER_O  = ../kernel/build/hg_reader.o

SRCS = src/main.cpp \
       src/util/hg_log.cpp \
       src/util/hg_config.cpp \
       src/bpf/hg_bpf_ctrl.cpp \
       src/http/hg_parser.cpp \
       src/http/hg_connection.cpp \
       src/http/hg_server.cpp \
       src/portal/hg_router.cpp \
       src/portal/hg_portal.cpp \
       src/portal/hg_auth.cpp

OBJS = $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean rebuild

all: $(TARGET)

$(TARGET): $(OBJS) $(READER_O)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

rebuild: clean all

clean:
	rm -rf $(BUILD_DIR)
