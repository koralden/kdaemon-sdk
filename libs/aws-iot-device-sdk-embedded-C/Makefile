# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Yellow Huang <yellow.huang@fikapark.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=aws-iot-device-sdk-embedded-C
PKG_VERSION:=202108.00
#PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/aws/aws-iot-device-sdk-embedded-C
PKG_SOURCE_DATE:=2021-08-00
PKG_SOURCE_VERSION:=9de6cc4e2cfda4cff8b6a5a3df5b9ab3a90e8f2c
PKG_MIRROR_HASH:=1db492340587b3938bdd1fe6eedfe20db45e1b06d62dcb676127fb66ada1e3f5

PKG_MAINTAINER:=Yellow Huang <yellow.huang@fikapark.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

#PKG_INSTALL:=1
#PKG_BUILD_PARALLEL:=1
CMAKE_BINARY_SUBDIR:=build

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/aws-iot-device-sdk-embedded-C
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=AWS IoT Device SDK for Embedded C
	URL:=https://github.com/aws/aws-iot-device-sdk-embedded-C#releases-and-documentation
	DEPENDS:=+libopenssl +libfika-mbedtls
endef
#DEPENDS:=+libopenssl +libmosquitto-nossl +libmbedtls
#	BUILDONLY:=1

define Package/aws-iot-device-sdk-embedded-C/description
	AWS IoT Device SDK for Embedded C
endef

CMAKE_OPTIONS += \
		 -DINSTALL_TO_SYSTEM=1 \
		 -DBUILD_DEMOS:BOOL=OFF \
		 -DBUILD_TESTS=0

#CMAKE_OPTIONS += -DBUILD_SHARED_LIBS:BOOL=OFF \
#	 -DCMAKE_BUILD_TYPE:STRING=Release
#	-DCMAKE_INSTALL_PREFIX:PATH=/usr 

define Build/InstallDev
	$(call Build/InstallDev/cmake,$(1))
endef

define Package/aws-iot-device-sdk-embedded-C/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib*.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,aws-iot-device-sdk-embedded-C))
