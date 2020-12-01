SRC_DIR:=$(shell cd "$(dirname "$0")"; pwd)/src
UTILS_DIR:=$(shell cd "$(dirname "$0")"; pwd)/utils
COMPILE_DIR:=$(shell cd "$(dirname "$0")"; pwd)/target
DST_DIR:=$(shell cd "$(dirname "$0")"; pwd)/target

CONFIG_ONLY_FOR_COMPILE := 

CFLAGS += -g -I../staging_dir/include -Iinclude -Iutils -Icomm/target/comm-0.0.1/install/include \
			-I$(LIB_DIR) -I$(LIB_INSTALL_DIR) \
			-DXLINK_DBG_PHASE $(if $(CONFIG_ONLY_FOR_COMPILE),-DONLY_FOR_COMPILE,)
LDFLAGS += ../staging_dir/lib/libcoap-2-openssl.a ../staging_dir/lib/libssl.a ../staging_dir/lib/libcrypto.a \
			-Lcomm/target/comm-0.0.1/install -lcomm -Wl,-rpath=comm/target/comm-0.0.1/install \
			-L$(SYSROOT)/lib -lpthread -lm -ldl \
			$(if $(CONFIG_ONLY_FOR_COMPILE),,$(LIBINSTALL_LDFLAGS) $(TCAPI_LIB))

BIN:=wflink.exe 
TEST_SERVER:=coapsrv.exe
SRC_FILES:=$(wildcard $(SRC_DIR)/*.c) $(wildcard $(UTILS_DIR)/*.c)
OBJ_FILES:=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(SRC_FILES)))
$(info ============)
$(info $(SRC_DIR))
$(info $(COMPILE_DIR))
$(info $(SRC_FILES))
$(info $(OBJ_FILES))
$(info ============)

all: prepare $(BIN) $(TEST_SERVER) install

$(COMPILE_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -o $@ -c $^ $(CFLAGS)

$(COMPILE_DIR)/%.o: $(UTILS_DIR)/%.c
	$(CC) -o $@ -c $^ $(CFLAGS)

libcomm:
	if [ -d comm/target ];then rm -rf comm/target; fi
	cd comm; make -f comm.mk; cd -;

prepare: libcomm
	mkdir -p $(COMPILE_DIR)
	mkdir -p $(DST_DIR)

$(BIN): $(OBJ_FILES)
	echo $(COMPILE_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TEST_SERVER):
	$(CC) -o $@ test/coap_server.c utils/cJSON.c $(CFLAGS) $(LDFLAGS)

install:
	cp $(BIN) $(FILESYSTEM_DIR)/userfs/bin/
	cp $(TEST_SERVER) $(FILESYSTEM_DIR)/userfs/bin/
	cp wflink.cfg $(FILESYSTEM_DIR)/usr/etc/

.PHONY: clean
clean:
	find $(COMPILE_DIR) -name "*.o" | xargs rm -rf
	find . -name "*.exe" | xargs rm -rf
