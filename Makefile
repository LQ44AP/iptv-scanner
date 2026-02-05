include $(TOPDIR)/rules.mk

PKG_NAME:=iptv-scanner
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/iptv-scanner
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=IPTV Multicast Scanner (Command Line Tool)
  DEPENDS:=+libpcap
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) \
		-I$(STAGING_DIR)/usr/include \
		-L$(STAGING_DIR)/usr/lib \
		$(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/iptv_scanner \
		./src/iptv_scanner.c \
		-lpcap
endef

define Package/iptv-scanner/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptv_scanner $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/iptv_scanner.config $(1)/etc/config/iptv_scanner
endef

$(eval $(call BuildPackage,iptv-scanner))
