################################################################################
#
# fika-easy-setup
#
################################################################################

FIKA_EASY_SETUP_VERSION = 0.01.0
#FIKA_EASY_SETUP_SITE = $(call github,sharkdp,bat,v$(FIKA_EASY_SETUP_VERSION))
FIKA_EASY_SETUP_SITE = $(TOPDIR)/package/longdong/net/fika-easy-setup/src
FIKA_EASY_SETUP_SITE_METHOD = local
FIKA_EASY_SETUP_LICENSE = Apache-2.0 or MIT
FIKA_EASY_SETUP_LICENSE_FILES = LICENSE-APACHE LICENSE-MIT

define FIKA_EASY_SETUP_BUILD_CMDS
	cd $($(PKG)_SRCDIR) && \
	$(TARGET_MAKE_ENV) \
		$(TARGET_CONFIGURE_OPTS) \
		$(PKG_CARGO_ENV) \
		cargo build \
			$(if $(BR2_ENABLE_DEBUG),,--release) \
			--manifest-path Cargo.toml \
			--locked
endef

FIKA_EASY_SETUP_MY_DIR=package/longdong/net/fika-easy-setup/files
define FIKA_EASY_SETUP_INSTALL_MISC
	$(INSTALL) -m 0755 -D $(FIKA_EASY_SETUP_MY_DIR)/fika-easy-setup.init \
		$(TARGET_DIR)/etc/init.d/S85fika-easy-setup
	$(INSTALL) -m 0755 -D $(FIKA_EASY_SETUP_MY_DIR)/fika-easy-setup.hotplug \
		$(TARGET_DIR)/etc/hotplug.d/iface/96-fika-easy-setup
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_easy_setup
	cp -a $(@D)/certs $(TARGET_DIR)/etc/fika_easy_setup
endef

FIKA_EASY_SETUP_POST_INSTALL_TARGET_HOOKS += FIKA_EASY_SETUP_INSTALL_MISC

$(eval $(cargo-package))
