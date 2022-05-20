# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Yellow Huang <yellow.huang@fikapark.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=aws-iot-device-sdk-cpp
PKG_VERSION:=1.17.0
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/aws/aws-iot-device-sdk-cpp-v2.git
PKG_SOURCE_DATE:=2022-05-18
PKG_SOURCE_VERSION:=1f54fd9864c054dc33e15b1144e2a6a19fa0a52e
PKG_SOURCE_VERSION:=1c457ab9ba156a488d04a373be84cd82849ffb07
PKG_MIRROR_HASH:=f12644bdaa0ba467cda2e64085d0a7f8b7bf44bcb30b4e33c23b4509e5f26644

PKG_MAINTAINER:=Yellow Huang <yellow.huang@fikapark.com>
PKG_LICENSE:=OpenSSL ISC
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=golang/host

FEED_PACKAGE_DIR:=$(TOPDIR)/feeds/packages
FEED_PACKAGE_LANG_DIR:=$(FEED_PACKAGE_DIR)/lang

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(FEED_PACKAGE_LANG_DIR)/golang/golang-values.mk

define Package/aws-iot-device-sdk-cpp
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=Amazon IOT device SDK CPP v2
	URL:=https://aws-iot-device-sdk-cpp.googlesource.com/aws-iot-device-sdk-cpp/
	DEPENDS:=+libstdcpp $(GO_ARCH_DEPENDS) @!(mips||mips64)
endef

define Package/aws-iot-device-sdk-cpp/description
	Amazon IOT device SDK CPP v2
endef

CMAKE_OPTIONS += \
		 -DCMAKE_INSTALL_PREFIX:PATH=/usr \
		 -DCMAKE_BUILD_TYPE:STRING=Release

define Package/aws-iot-device-sdk-cpp/install
endef

define Build/InstallDev
endef

$(eval $(call BuildPackage,aws-iot-device-sdk-cpp))
