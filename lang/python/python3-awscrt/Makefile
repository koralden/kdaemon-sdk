include $(TOPDIR)/rules.mk

PKG_NAME:=awscrt
PKG_VERSION:=0.13.11
PKG_RELEASE:=2

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=631dc8dd10f9ecdc7a0af9b89a8739ce631b76c1de6223208437db414a2bdfc1

PKG_MAINTAINER:=Yellow Huang <yellow.huang@fikapark.com>
PKG_LICENSE:=MIT

include ../pypi.mk
include $(INCLUDE_DIR)/package.mk
#include $(INCLUDE_DIR)/cmake.mk
include ../python3-package.mk
include ../../golang/golang-values.mk
PKG_BUILD_DEPENDS:=golang/host perl/host boringssl

define Package/python3-awscrt
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=awscrt
  URL:=https://github.com/awslabs/aws-crt-python.git
  DEPENDS:=+python3 +boringssl
endef

define Package/python3-awscrt/description
Python 3 bindings for the AWS Common Runtime.
endef

#CMAKE_OPTIONS+=-DBUILD_SHARED_LIBS=ON
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib/boringssl -lssl -lcrypto

# TODO, /usr/lib/boringssl/lib{crypto,ssl}.so not found default
# workaround, (1) symblic-link created or 
# (2) specific LD_LIBRARY_PATH(in /etc/profile.d)

$(eval $(call Py3Package,python3-awscrt))
$(eval $(call BuildPackage,python3-awscrt))
$(eval $(call BuildPackage,python3-awscrt-src))
