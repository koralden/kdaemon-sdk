################################################################################
#
# fika-iot-gateway
#
################################################################################

FIKA_IOT_GATEWAY_VERSION = 71cbc74eb0ea277846eb441ad8ac2033d299857d
#FIKA_IOT_GATEWAY_SITE = git@github.com:koralden/longdong.git
#FIKA_IOT_GATEWAY_SITE_METHOD = git
#FIKA_IOT_GATEWAY_SUBDIR = net/fika-iot-gateway/src
FIKA_IOT_GATEWAY_SITE = $(TOPDIR)/package/longdong/net/fika-iot-gateway/src
FIKA_IOT_GATEWAY_SITE_METHOD = local
FIKA_IOT_GATEWAY_LICENSE = MIT
FIKA_IOT_GATEWAY_LICENSE_FILES = LICENSE
#FIKA_IOT_GATEWAY_INSTALL_STAGING = YES
FIKA_IOT_GATEWAY_INSTALL_TARGET = YES
FIKA_IOT_GATEWAY_DEPENDENCIES = openssl libuv hiredis libyaml aws-iot-device-sdk-embedded-C
FIKA_IOT_GATEWAY_CONF_OPTS = -DSDK_DIR=$(STAGING_DIR)/usr
FIKA_IOT_GATEWAY_SUPPORTS_IN_SOURCE_BUILD = NO

define MANUAL_PATCH
	@$(call MESSAGE,"Manual Patching")
	for D in $(FIKA_IOT_GATEWAY_PKGDIR); do \
	  if test -d $${D}; then \
	      $(APPLY_PATCHES) $(@D) $${D} \*.patch \*.patch.$(ARCH) || exit 1; \
	  fi; \
	done;
endef

FIKA_IOT_GATEWAY_POST_RSYNC_HOOKS += MANUAL_PATCH

$(eval $(cmake-package))
