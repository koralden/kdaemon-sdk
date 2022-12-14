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

#FIKA_MANAGER_CARGO_ENV = TARGET_CC=$(TARGET_CC) TARGET_AR=$(TARGET_AR) CARGO_CFG_TARGET_ARCH="aarch64" TARGET="aarch64-unknown-linux-musl" RUST_BACKTRACE=1

define FIKA_MANAGER_BUILD_CMDS
          cd $($(PKG)_SRCDIR) && \
          $(TARGET_MAKE_ENV) \
                  $(TARGET_CONFIGURE_OPTS) \
                  $(PKG_CARGO_ENV) \
                  $($(2)_CARGO_ENV) \
                  cargo build \
                          $(if $(BR2_ENABLE_DEBUG),,--release) \
                          --manifest-path Cargo.toml \
                          --locked \
                          $($(2)_CARGO_BUILD_OPTS)
endef

FIKA_MANAGER_MY_DIR=package/longdong/system/fika-manager/files
FIKA_MANAGER_MY_SCRIPT=easy_setup.sh heartbeat.sh common.sh \
	     provision.sh cmp_remote_manage.sh boss_ap_info.sh \
	     cmp_ap_info.sh activation.sh por_config.sh \
	     hcs_honest_challenge.sh boss_token.sh misc.sh \
	     factory/post_core.sh factory/post_wifi_ssid_by_uci.sh \
	     factory/post_boss.sh factory/post_cmp.sh \
	     factory/pre_core.sh factory/post_por.sh
define FIKA_MANAGER_INSTALL_MISC
	$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/fika-manager.init \
		$(TARGET_DIR)/etc/init.d/fika-manager
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/rule.toml.sample $(TARGET_DIR)/etc/fika_manager/rule.toml
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/activate.toml.sample $(TARGET_DIR)/etc/fika_manager/activate.toml
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/kdaemon.toml.sample $(TARGET_DIR)/etc/fika_manager/kdaemon.toml.sample
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/bootstrap-inactive.certificate.pem $(TARGET_DIR)/etc/fika_manager/bootstrap-inactive.certificate.pem
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/bootstrap-inactive.private.key $(TARGET_DIR)/etc/fika_manager/bootstrap-inactive.private.key
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/AmazonRootCA1.pem $(TARGET_DIR)/etc/fika_manager/AmazonRootCA1.pem
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/factory
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/thirdparty
	for i in $(FIKA_MANAGER_MY_SCRIPT); do \
		$(INSTALL) -m 0755 -D $(FIKA_MANAGER_MY_DIR)/$${i} $(TARGET_DIR)/etc/fika_manager/$${i}; \
	done
	$(INSTALL) -d $(TARGET_DIR)/etc/hotplug.d/iface
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_MY_DIR)/97-fika-manager.hotplug $(TARGET_DIR)/etc/hotplug.d/iface/97-fika-manager
endef

FIKA_MANAGER_POST_INSTALL_TARGET_HOOKS += FIKA_MANAGER_INSTALL_MISC

$(eval $(cargo-package))
