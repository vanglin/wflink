PKG_BUILD_DIR:=$(shell cd "$(dirname "$0")"; pwd)
COMPILE_DIR:=$(PKG_BUILD_DIR)
CFLAGS+= -I$(PKG_BUILD_DIR)/install/include
LDFLAGS+=-L$(PKG_BUILD_DIR)/install
export DESTDIR=$(PKG_BUILD_DIR)
export STAGING_DIR
export TOOLCHAIN_DIR


cflags:= -fPIC -DSOCKET_THREAD $(CFLAGS) -I$(LIB_INSTALL_DIR) -I$(PKG_BUILD_DIR)/ -I$(COMPILE_DIR)/socket/ -I$(COMPILE_DIR)/string/ -I$(COMPILE_DIR)/thread_queue/ -I$(COMPILE_DIR)/timer/ -I$(COMPILE_DIR)/state_machine/
ldflags:= $(LDFLAGS) -L$(LIB_INSTALL_DIR) -L$(PKG_BUILD_DIR)/install -lpthread -lrt

all: libcomm


CUR_SRC=$(wildcard $(COMPILE_DIR)/*.c)
CUR_OBJ=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(CUR_SRC)))

socket_src=$(wildcard $(COMPILE_DIR)/socket/*.c)
socket_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(socket_src)))

string_src=$(wildcard $(COMPILE_DIR)/string/*.c)
string_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(string_src)))


timer_src=$(wildcard $(COMPILE_DIR)/timer/*.c)
timer_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(timer_src)))

ifdef COMM_TIMER
timer_src=$(wildcard $(COMPILE_DIR)/timer/*.c)
timer_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(timer_src)))
else
timer_obj:=
endif

ifdef COMM_THREADPOOL
thread_queue_src=$(wildcard $(COMPILE_DIR)/thread_queue/*.c)
thread_queue_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(thread_queue_src)))
else
thread_queue_obj:=
endif

ifdef COMM_STATEMACHINE
state_machine_src=$(wildcard $(COMPILE_DIR)/state_machine/*.c)
state_machine_obj=$(patsubst %.c,$(COMPILE_DIR)/%.o,$(notdir $(state_machine_src)))
else
state_machine_obj:=
endif

$(timer_obj):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/timer/%.c,$(notdir $@))

$(string_obj):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/string/%.c,$(notdir $@))

$(socket_obj):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/socket/%.c,$(notdir $@))

$(thread_queue_obj):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/thread_queue/%.c,$(notdir $@))

$(state_machine_obj):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/state_machine/%.c,$(notdir $@))

$(CUR_OBJ):
	$(CC) $(cflags) $(ldflags) -o $@ -c $(patsubst %.o,$(COMPILE_DIR)/%.c,$(notdir $@))

libcomm: $(CUR_OBJ) $(socket_obj) $(string_obj) $(timer_obj) $(thread_queue_obj) $(state_machine_obj)
	$(CC) -shared -o $@.so $^ $(cflags) $(ldflags)
clean:
	rm -rf $(PKG_BUILD_DIR)/*.*o
	rm -rf $(PKG_BUILD_DIR)/install
install:all
	@echo " install all"
	mkdir -p $(PKG_BUILD_DIR)/install/include
	cp -ar libcomm.so $(PKG_BUILD_DIR)/install/
	cp -ar $(PKG_BUILD_DIR)/*.h $(PKG_BUILD_DIR)/install/include
	cp -ar $(PKG_BUILD_DIR)/socket/*.h $(PKG_BUILD_DIR)/install/include
	cp -ar $(PKG_BUILD_DIR)/string/*.h $(PKG_BUILD_DIR)/install/include
	cp -ar $(PKG_BUILD_DIR)/thread_queue/*.h $(PKG_BUILD_DIR)/install/include
	cp -ar $(PKG_BUILD_DIR)/timer/*.h $(PKG_BUILD_DIR)/install/include
	cp -ar $(PKG_BUILD_DIR)/state_machine/*.h $(PKG_BUILD_DIR)/install/include
