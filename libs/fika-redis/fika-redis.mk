################################################################################
#
# redis
#
################################################################################

FIKA_REDIS_VERSION = 7.0.0
FIKA_REDIS_SOURCE = redis-$(FIKA_REDIS_VERSION).tar.gz
FIKA_REDIS_SITE = http://download.redis.io/releases
FIKA_REDIS_LICENSE = BSD-3-Clause (core); MIT and BSD family licenses (Bundled components)
FIKA_REDIS_LICENSE_FILES = COPYING
FIKA_REDIS_CPE_ID_VENDOR = redislabs
FIKA_REDIS_SELINUX_MODULES = redis

define FIKA_REDIS_USERS
	redis -1 redis -1 * /var/lib/redis /bin/false - Redis Server
endef

# Uses __atomic_fetch_add_4. Adding -latomic to LDFLAGS does not work,
# because LDFLAGS is used before the list of object files. We need to
# add -latomic to FINAL_LIBS to provide -latomic at the correct place
# in the linking command.
ifeq ($(BR2_TOOLCHAIN_HAS_LIBATOMIC),y)
define FIKA_REDIS_FIX_MAKEFILE
	$(SED) 's/FINAL_LIBS=-lm/FINAL_LIBS=-lm -latomic/' $(@D)/src/Makefile
endef
FIKA_REDIS_POST_PATCH_HOOKS = FIKA_REDIS_FIX_MAKEFILE
endif

# Redis doesn't support DESTDIR (yet, see
# https://github.com/antirez/redis/pull/609).  We set PREFIX
# instead.
FIKA_REDIS_BUILDOPTS = $(TARGET_CONFIGURE_OPTS) \
	PREFIX=$(TARGET_DIR)/usr MALLOC=libc

ifeq ($(BR2_PACKAGE_SYSTEMD),y)
FIKA_REDIS_DEPENDENCIES += systemd
FIKA_REDIS_BUILDOPTS += USE_SYSTEMD=yes
else
FIKA_REDIS_BUILDOPTS += USE_SYSTEMD=no
endif

ifeq ($(BR2_PACKAGE_LIBOPENSSL),y)
FIKA_REDIS_DEPENDENCIES += libopenssl
FIKA_REDIS_BUILDOPTS += BUILD_TLS=yes
else
FIKA_REDIS_BUILDOPTS += BUILD_TLS=no
endif

define FIKA_REDIS_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(MAKE) $(FIKA_REDIS_BUILDOPTS) -C $(@D)
endef

define FIKA_REDIS_INSTALL_TARGET_CMDS
	$(TARGET_MAKE_ENV) $(MAKE) $(FIKA_REDIS_BUILDOPTS) -C $(@D) \
		LDCONFIG=true install
	$(INSTALL) -D -m 0644 package/longdong/libs/fika-redis/files/fika_redis.conf.sample \
		$(TARGET_DIR)/etc/fika-redis.conf.sample
endef

define FIKA_REDIS_INSTALL_INIT_SYSV
	$(INSTALL) -m 0755 -D package/longdong/libs/fika-redis/files/redis.init.buildroot \
		$(TARGET_DIR)/etc/init.d/fika-redis
endef

define FIKA_REDIS_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 package/longdong/libs/fika-redis/files/redis.service.buildroot \
		$(TARGET_DIR)/usr/lib/systemd/system/fika-redis.service
endef

$(eval $(generic-package))
