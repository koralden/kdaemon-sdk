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

$(eval $(cargo-package))
