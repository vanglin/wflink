include $(TOPDIR)/rules.mk

PKG_NAME:=comm
PKG_VERSION:=0.0.1

include $(INCLUDE_DIR)/package.mk


PJFLAGS:=-DPJ_LIST_EX -Ilibpjextend/src/include
PJLIBFLAGS:=-lpjextend

PKG_CONFIG_DEPENDS := \
	CONFIG_COMM_TIMER \
	CONFIG_COMM_THREADPOOL \
	CONFIG_COMM_PJLIB


define Package/comm
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:= +libpthread +librt +COMM_PJLIB:libpjextend +libcurl
  TITLE:=Library ported from base lib to support voip
  MENU:=1
endef

define Package/comm/config
  source "$(SOURCE)/Config.in"
endef

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)



define Build/Configure
	mkdir -p $(PKG_BUILD_DIR)
	cp -ar ./src/* $(PKG_BUILD_DIR)
	#sed -i "s%^COMPILE_DIR=\(.*\)%COMPILE_DIR=$(PKG_BUILD_DIR)%" $(PKG_BUILD_DIR)/Makefile
endef
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) install \
	CC="$(TARGET_CC)" \
	AR="$(TARGET_CROSS)ar" \
	CFLAGS="-g -fPIC -I$(LINUX_DIR)/include -I$(STAGING_DIR)/usr/include -I$(TOOLCHAIN_DIR)/include -I$(PKG_BUILD_DIR)/include \
		$(if $(CONFIG_COMM_TIMER),-DCOMM_TIMER,) \
		$(if $(CONFIG_COMM_THREADPOOL),-DTHREADPOOL,) \
		$(if $(CONFIG_COMM_PJLIB),-DPJ_LIST_EX -Ilibpjextend/src/include,) \
		$(if $(CONFIG_COMM_DEBUG),-DSIG_LOCK_DEBUG,)" \
	LDFLAGS="-L$(STAGING_DIR)/usr/lib -lpthread -lrt $(if $(CONFIG_COMM_PJLIB),-lpjextend,)" \
	$(if $(CONFIG_COMM_TIMER),COMM_TIMER=1,) \
	$(if $(CONFIG_COMM_THREADPOOL),COMM_THREADPOOL=1,)
endef

define Build/InstallDev
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_BUILD_DIR)/install/libcomm.so $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/install/include/*.h $(STAGING_DIR)/usr/include/
endef
	
define Build/UninstallDev
	rm -rf	$(STAGING_DIR)/usr/lib/libcomm.{a,so*}
endef

define Package/comm/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/install/libcomm.so $(1)/usr/lib/
endef
$(eval $(call BuildPackage,comm))
