#TOP_DIR ?= $(shell hg root)
#include $(TOP_DIR)/makeRule/make.common

PKG_NAME := comm
PKG_VERSION := 0.0.1

CONFIG_COMM_TIMER := y
CONFIG_COMM_THREADPOOL := y
CONFIG_COMM_STATEMACHINE := y
CONFIG_COMM_PJLIB := 
CONFIG_COMM_DEBUG := 

PJFLAGS:=-DPJ_LIST_EX -Ilibpjextend/src/include
PJLIBFLAGS:=-lpjextend

define Package/comm
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:= +libpthread +librt +COMM_PJLIB:libpjextend
  TITLE:=Library ported from base lib to support voip
  MENU:=1
endef

TARGET_CC:= $(CC)
TARGET_CROSS := 
LINUX_DIR := 
STAGING_DIR := 
TOOLCHAIN_DIR :=
BUILD_DIR := ./target
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

all: prepare build install

prepare:
	mkdir -p $(PKG_BUILD_DIR)
	cp -ar ./src/* $(PKG_BUILD_DIR)
	#sed -i "s%^COMPILE_DIR=\(.*\)%COMPILE_DIR=$(PKG_BUILD_DIR)%" $(PKG_BUILD_DIR)/Makefile

build:
	$(MAKE) -C $(PKG_BUILD_DIR) install \
	CC="$(TARGET_CC)" \
	AR="$(TARGET_CROSS)ar" \
	CFLAGS="-g -fPIC -I$(PKG_BUILD_DIR)/include \
		$(if $(CONFIG_COMM_TIMER),-DCOMM_TIMER,) \
		$(if $(CONFIG_COMM_THREADPOOL),-DTHREADPOOL,) \
		$(if $(CONFIG_COMM_PJLIB),-DPJ_LIST_EX -Ilibpjextend/src/include,) \
		$(if $(CONFIG_COMM_DEBUG),-DSIG_LOCK_DEBUG,)" \
	LDFLAGS="-L$(LIB_INSTALL_DIR) -lpthread -lrt $(if $(CONFIG_COMM_PJLIB),-lpjextend,)" \
	$(if $(CONFIG_COMM_TIMER),COMM_TIMER=1,) \
	$(if $(CONFIG_COMM_THREADPOOL),COMM_THREADPOOL=1,) \
	$(if $(CONFIG_COMM_STATEMACHINE),COMM_STATEMACHINE=1,)

installDev:
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_BUILD_DIR)/install/libcomm.so $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/install/include/*.h $(STAGING_DIR)/usr/include/

uninstallDev:
	rm -rf	$(STAGING_DIR)/usr/lib/libcomm.{a,so*}

install:
	cp $(PKG_BUILD_DIR)/install/libcomm.so $(LIB_INSTALL_DIR)/
	cp $(PKG_BUILD_DIR)/install/libcomm.so $(FILESYSTEM_DIR)/lib/
