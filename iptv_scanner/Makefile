include $(TOPDIR)/rules.mk

PKG_NAME:=iptv_scanner
PKG_VERSION:=1.0.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/iptv_scanner
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IPTV Multicast Scanner
  DEPENDS:=+libpcap
endef

define Package/iptv_scanner/description
  A lightweight IPTV multicast scanner.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) \
		-o $(PKG_BUILD_DIR)/iptv_scanner \
		$(PKG_BUILD_DIR)/iptv_scanner.c \
		$(TARGET_LDFLAGS) -lpcap
endef

define Package/iptv_scanner/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptv_scanner $(1)/usr/bin/
endef

$(eval $(call BuildPackage,iptv_scanner))
