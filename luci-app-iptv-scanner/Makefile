include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-iptv-scanner
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI app for IPTV multicast scanner
LUCI_DEPENDS:=+iptv_scanner +rpcd +rpcd-mod-file
LUCI_PKGARCH:=all

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
