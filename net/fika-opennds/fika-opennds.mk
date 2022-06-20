################################################################################
#
# fika-iot-gateway
#
################################################################################

FIKA_OPENNDS_VERSION = 9.7.0
#FIKA_OPENNDS_SITE = $(call github,opennds,opennds,v$(FIKA_OPENNDS_VERSION))
FIKA_OPENNDS_SOURCE = v$(FIKA_OPENNDS_VERSION).tar.gz
FIKA_OPENNDS_SITE = https://github.com/openNDS/openNDS/archive/refs/tags
FIKA_OPENNDS_LICENSE = GPL-2.0-or-later
FIKA_OPENNDS_LICENSE_FILES = COPYING
#FIKA_OPENNDS_INSTALL_STAGING = YES
FIKA_OPENNDS_INSTALL_TARGET = YES
FIKA_OPENNDS_DEPENDENCIES = libmicrohttpd

#define MANUAL_PATCH
#	@$(call MESSAGE,"Manual Patching")
#	for D in $(FIKA_OPENNDS_PKGDIR); do \
#	  if test -d $${D}; then \
#	      $(APPLY_PATCHES) $(@D) $${D} \*.patch \*.patch.$(ARCH) || exit 1; \
#	  fi; \
#	done;
#endef
#
#FIKA_OPENNDS_POST_RSYNC_HOOKS += MANUAL_PATCH

define FIKA_OPENNDS_BUILD_CMDS
	$(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(@D) all
endef

define FIKA_OPENNDS_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/opennds $(TARGET_DIR)/usr/bin/opennds
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/opennds/
	echo "TODO"
endef

$(eval $(generic-package))
