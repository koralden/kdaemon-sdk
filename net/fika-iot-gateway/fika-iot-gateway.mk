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

define FIKA_IOT_GATEWAY_MANUAL_PATCH
	if ! test -e $(@D)/.MANUAL_PATCH; then \
		@$(call MESSAGE,"Manual Patching"); \
		for D in $(FIKA_IOT_GATEWAY_PKGDIR); do \
		  if test -d $${D}; then \
		      $(APPLY_PATCHES) $(@D) $${D} \*.patch \*.patch.$(ARCH) || exit 1; \
		  fi; \
		done; \
		touch $(@D)/.MANUAL_PATCH; \
	fi
endef

FIKA_IOT_GATEWAY_POST_RSYNC_HOOKS += FIKA_IOT_GATEWAY_MANUAL_PATCH

FIKA_IOT_GATEWAY_MY_DIR=package/longdong/net/fika-iot-gateway/files
FIKA_IOT_GATEWAY_MY_FILES=fika_iot_gateway.yaml MVP_000001-certificate.pem.crt MVP_000001-private.pem.key AmazonRootCA1.pem AmazonRootCA3.pem
define FIKA_IOT_GATEWAY_INSTALL_MISC
	$(INSTALL) -m 0755 -D $(FIKA_IOT_GATEWAY_MY_DIR)/fika_iot_gateway.init \
		$(TARGET_DIR)/etc/init.d/fika-iot-gateway
	$(INSTALL) -m 0755 -D $(FIKA_IOT_GATEWAY_MY_DIR)/fika-iot-gateway.hotplug \
		$(TARGET_DIR)/etc/hotplug.d/iface/90-fika-iot-gateway
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_iot_gateway
	for i in $(FIKA_IOT_GATEWAY_MY_FILES); do \
		$(INSTALL) -m 0644 -D $(FIKA_IOT_GATEWAY_MY_DIR)/$${i} \
			$(TARGET_DIR)/etc/fika_iot_gateway/$${i}; \
	done
endef

FIKA_IOT_GATEWAY_POST_INSTALL_TARGET_HOOKS += FIKA_IOT_GATEWAY_INSTALL_MISC


$(eval $(cmake-package))
