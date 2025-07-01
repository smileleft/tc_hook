# Makefile for TC Block Example

# Define source and build directories
SRC_DIR := src
BUILD_DIR := build

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

ARCH_INCLUDE_PATH := /usr/include/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

# Source files
TC_KERN_SRC := $(SRC_DIR)/tc_block_tcp_kern.bpf.c

# Output files
TC_KERN_OBJ := $(BUILD_DIR)/tc_block_tcp_kern.bpf.o

# Compiler flags
CLANG_CFLAGS := -g -O2 -target bpf -I/usr/include/bpf -I$(ARCH_INCLUDE_PATH)
LIBS := # TC 예제는 사용자 공간 앱이 없으므로 라이브러리 필요 없음

# Phony targets
.PHONY: all clean

all: $(BUILD_DIR) $(TC_KERN_OBJ)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TC_KERN_OBJ): $(TC_KERN_SRC)
	clang $(CLANG_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
