# === 项目配置 ===
TARGET      := nfq_handler
SRCS        := nfq_handler.c dns_utils.c
OBJS        := $(SRCS:.c=.o)

# === 目录 ===
BUILD_DIR   := build
BIN_DIR     := bin
OUT_BIN     := $(BIN_DIR)/$(TARGET)

# === 编译器及选项 ===
CC          := gcc
CFLAGS      := -Wall -Wextra -g -O2 -I.
LDFLAGS     := -L/usr/lib -lnetfilter_queue -lresolv

# === 系统工具变量 ===
RM          := rm -f
MKDIR       := mkdir -p
INSTALL     := sudo iptables

# === NFQUEUE 配置 ===
QUEUE_NUM   := 100
PROTO       := udp
PORT        := 53

# === 默认目标 ===
.PHONY: all
all: $(OUT_BIN)

# 创建 bin/ 和 build/ 并编译
$(OUT_BIN): $(addprefix $(BUILD_DIR)/, $(OBJS))
	@$(MKDIR) $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@$(MKDIR) $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# === 安装规则 ===
.PHONY: install
install:
	@echo "添加 iptables NFQUEUE 规则..."
	# $(INSTALL) -I OUTPUT -p $(PROTO) --dport $(PORT) -j NFQUEUE --queue-num $(QUEUE_NUM)
	$(INSTALL) -I INPUT  -p $(PROTO) --sport $(PORT) -j NFQUEUE --queue-num $(QUEUE_NUM)

# === 卸载规则 ===
.PHONY: uninstall
uninstall:
	@echo "移除 iptables NFQUEUE 规则..."
	# -$(INSTALL) -D OUTPUT -p $(PROTO) --dport $(PORT) -j NFQUEUE --queue-num $(QUEUE_NUM)
	-$(INSTALL) -D INPUT  -p $(PROTO) --sport $(PORT) -j NFQUEUE --queue-num $(QUEUE_NUM)

# === 清理 ===
.PHONY: clean
clean:
	$(RM) $(BUILD_DIR)/*.o $(OUT_BIN)

.PHONY: rebuild
rebuild: clean all
