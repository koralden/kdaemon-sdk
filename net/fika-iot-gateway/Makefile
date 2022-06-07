# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Yellow Huang <yellow.huang@fikapark.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=fika-iot-gateway
PKG_VERSION:=1.0.0
PKG_RELEASE:=0

PKG_MAINTAINER:=Yellow Huang <yellow.huang@fikapark.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

CMAKE_BINARY_SUBDIR:=build

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/fika-iot-gateway
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Fika IOT gateway for AWS IoT Core
	URL:=https://github.com:koralden/longdong.git
	DEPENDS:=+libuv +libhiredis +aws-iot-device-sdk-embedded-C +libyaml
endef

define Package/fika-iot-gateway/description
	Fika IOT gateway for AWS IoT Core
endef

#CMAKE_OPTIONS += \
#		 -DINSTALL_TO_SYSTEM=1 \
#		 -DBUILD_DEMOS:BOOL=OFF \
#		 -DBUILD_TESTS=0

#CMAKE_OPTIONS += -DBUILD_SHARED_LIBS:BOOL=OFF \
#	 -DCMAKE_BUILD_TYPE:STRING=Release
#	-DCMAKE_INSTALL_PREFIX:PATH=/usr 

#define Build/InstallDev
#	$(call Build/InstallDev/cmake,$(1))
#	$(SED) 's,/usr/include,$$$${prefix}/include,g' $(1)/usr/lib/pkgconfig/libuv.pc
#	$(SED) 's,/usr/lib,$$$${prefix}/lib,g' $(1)/usr/lib/pkgconfig/libuv.pc
#	$(SED) 's,/usr/include,$$$${prefix}/include,g' $(1)/usr/lib/pkgconfig/libuv-static.pc
#	$(SED) 's,/usr/lib,$$$${prefix}/lib,g' $(1)/usr/lib/pkgconfig/libuv-static.pc
#endef

define Package/fika-iot-gateway/conffiles
/etc/fika_iot_gateway/fika_iot_gateway.yaml
endef

define Package/fika-iot-gateway/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/fika_iot_gateway $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fika_iot_gateway.init $(1)/etc/init.d/fika_iot_gateway
	$(INSTALL_DIR) $(1)/etc/fika_iot_gateway
	$(INSTALL_DATA) ./files/fika_iot_gateway.yaml $(1)/etc/fika_iot_gateway
	# install test key/ca!? 
	$(INSTALL_DATA) ./files/AmazonRootCA1.pem $(1)/etc/fika_iot_gateway
	$(INSTALL_DATA) ./files/AmazonRootCA3.pem $(1)/etc/fika_iot_gateway
	$(INSTALL_DATA) ./files/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-certificate.pem.crt $(1)/etc/fika_iot_gateway
	$(INSTALL_DATA) ./files/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-private.pem.key $(1)/etc/fika_iot_gateway
endef

$(eval $(call BuildPackage,fika-iot-gateway))
