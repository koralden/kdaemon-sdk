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
FIKA_MANAGER_MY_SCRIPT=easy_setup.sh heartbeat.sh common.sh captive-portal.sh \
	     maker.sh provision.sh runtime_statistics.sh \
	     nms_remote_manage.sh system_checking.sh por_config.sh \
	     cmp_pairing.sh hcs_honest_challenge.sh boss_token.sh \
	     thirdparty/firewall.sh thirdparty/network.sh thirdparty/system.sh \
	     factory/post_core.sh factory/post_wifi_ssid_by_uci.sh \
	     factory/post_boss.sh factory/post_cmp.sh \
	     factory/pre_core.sh
define FIKA_MANAGER_INSTALL_MISC
	$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/fika-manager.init \
		$(TARGET_DIR)/etc/init.d/fika-manager
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/config.toml $(TARGET_DIR)/etc/fika_manager/config.toml
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/factory.toml $(TARGET_DIR)/etc/fika_manager/factory.toml
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/factory
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/thirdparty
	for i in $(FIKA_MANAGER_MY_SCRIPT); do \
		$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/$${i} $(TARGET_DIR)/etc/fika_manager/$${i}; \
	done
	$(INSTALL) -d $(TARGET_DIR)/etc/hotplug.d/iface
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/97-fika-manager.hotplug $(TARGET_DIR)/$(TARGET_DIR)/etc/hotplug.d/iface/97-fika-manager
endef

FIKA_MANAGER_POST_INSTALL_TARGET_HOOKS += FIKA_MANAGER_INSTALL_MISC

$(eval $(cargo-package))
