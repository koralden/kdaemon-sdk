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

$(eval $(cargo-package))
