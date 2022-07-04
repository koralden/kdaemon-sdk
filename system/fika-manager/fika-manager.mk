################################################################################
#
# fika-easy-setup
#
################################################################################

FIKA_MANAGER_VERSION = 0.01.0
FIKA_MANAGER_SITE = $(TOPDIR)/package/longdong/system/fika-manager/src
FIKA_MANAGER_SITE_METHOD = local
FIKA_MANAGER_LICENSE = Apache-2.0 or MIT
FIKA_MANAGER_LICENSE_FILES = LICENSE-APACHE LICENSE-MIT

define FIKA_MANAGER_BUILD_CMDS
	cd $($(PKG)_SRCDIR) && \
	$(TARGET_MAKE_ENV) \
		$(TARGET_CONFIGURE_OPTS) \
		$(PKG_CARGO_ENV) \
		cargo build \
			$(if $(BR2_ENABLE_DEBUG),,--release) \
			--manifest-path Cargo.toml \
			--locked
endef

FIKA_MANAGER_MY_DIR=package/longdong/system/fika-manager/files
FIKA_MANAGER_MY_SCRIPT=easy_setup.sh  heartbeat.sh common.sh captive-portal.sh \
	     maker.sh provision.sh remote_manage.sh runtime_statistics.sh \
	     thirdparty/firewall.sh thirdparty/network.sh thirdparty/system.sh
define FIKA_MANAGER_INSTALL_MISC
	$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/fika-manager.init \
		$(TARGET_DIR)/etc/init.d/fika-manager
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/config.toml $(TARGET_DIR)/etc/fika_manager/config.toml
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/thirdparty
	for i in $(FIKA_MANAGER_MY_SCRIPT); do \
		$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/$${i} $(TARGET_DIR)/etc/fika_manager/$${i}; \
	done
endef

FIKA_MANAGER_POST_INSTALL_TARGET_HOOKS += FIKA_MANAGER_INSTALL_MISC

$(eval $(cargo-package))
