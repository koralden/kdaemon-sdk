include $(TOPDIR)/rules.mk

PKG_NAME:=awsiotsdk
PKG_VERSION:=1.11.1
PKG_RELEASE:=2

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=41cdcad04f2bfadaf8231b9a02eebfb85e3d6ecb6cbec2441c0fda6ca323871e

PKG_MAINTAINER:=Yellow Huang <yellow.huang@fikapark.com>
PKG_LICENSE:=MIT

include ../pypi.mk
include $(INCLUDE_DIR)/package.mk
include ../python3-package.mk

define Package/python3-awsiotsdk
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=awsiotsdk
  URL:=https://github.com/aws/aws-iot-device-sdk-python-v2.git
  DEPENDS:=+python3 +python3-awscrt
endef

define Package/python3-awsiotsdk/description
This package provides interface to Amazon IOT core/device service
endef

$(eval $(call Py3Package,python3-awsiotsdk))
$(eval $(call BuildPackage,python3-awsiotsdk))
$(eval $(call BuildPackage,python3-awsiotsdk-src))
