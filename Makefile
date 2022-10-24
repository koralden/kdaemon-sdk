#TARGET_DIR ?= ""
INSTALL ?= "install"

all: build


build: cargo-fika-manager cargo-fika-easy-setup

cargo-fika-manager:
	cargo install --path system/fika-manager/src

cargo-fika-easy-setup:
	cargo install -F pairing-only --path net/fika-easy-setup/src

install: install-fika-manager install-fika-easy-setup


FIKA_MANAGER_SRC_DIR=system/fika-manager/files
FIKA_MANAGER_SRC_SCRIPT=misc.sh common.sh \
	heartbeat.sh provision.sh \
	cmp_ap_info.sh boss_ap_info.sh \
	factory/post_core.sh factory/pre_core.sh \
	factory/post_boss.sh factory/post_cmp.sh 

install-fika-manager:
	$(INSTALL) -m 0755 -D system/fika-manager/src/target/release/fika-manager $(TARGET_DIR)/usr/bin/fika-manager
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/rule.toml.sample $(TARGET_DIR)/etc/fika_manager/rule.toml
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/activate.toml.sample $(TARGET_DIR)/etc/fika_manager/activate.toml
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/kdaemon.toml.sample $(TARGET_DIR)/etc/fika_manager/kdaemon.toml.sample
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/bootstrap-sdk.certificate.pem $(TARGET_DIR)/etc/fika_manager/bootstrap-sdk.certificate.pem
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/bootstrap-sdk.private.key $(TARGET_DIR)/etc/fika_manager/bootstrap-sdk.private.key
	$(INSTALL) -m 0644 -D $(FIKA_MANAGER_SRC_DIR)/AmazonRootCA1.pem $(TARGET_DIR)/etc/fika_manager/AmazonRootCA1.pem
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_manager/factory
	for i in $(FIKA_MANAGER_SRC_SCRIPT); do \
		$(INSTALL) -m 0755 -D $(FIKA_MANAGER_SRC_DIR)/$${i} $(TARGET_DIR)/etc/fika_manager/$${i}; \
	done

FIKA_EASY_SETUP_SRC_DIR=net/fika-easy-setup/src

install-fika-easy-setup:
	$(INSTALL) -m 0755 -D net/fika-easy-setup/src/target/release/fika-easy-setup $(TARGET_DIR)/usr/bin/fika-easy-setup
	$(INSTALL) -d $(TARGET_DIR)/etc/fika_easy_setup
	cp -a $(FIKA_EASY_SETUP_SRC_DIR)/certs $(TARGET_DIR)/etc/fika_easy_setup
	cp -a $(FIKA_EASY_SETUP_SRC_DIR)/templates/assets $(TARGET_DIR)/etc/fika_easy_setup


.PHONY: all build
.PHONY: cargo-fika-manager install-fika-manager
.PHONY: cargo-fika-easy-setup install-fika-easy-setup
