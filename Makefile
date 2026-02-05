include $(TOPDIR)/rules.mk

PKG_NAME:=iptv-scanner
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/iptv-scanner
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=IPTV Multicast Scanner
  DEPENDS:=+libpcap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/iptv-scanner/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptv_scanner $(1)/usr/bin/
endef

$(eval $(call BuildPackage,iptv-scanner))