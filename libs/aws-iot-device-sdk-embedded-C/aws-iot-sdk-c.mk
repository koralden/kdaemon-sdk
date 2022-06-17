################################################################################
#
# aws-iot-sdk-c
#
################################################################################

AWS_IOT_DEVICE_SDK_EMBEDDED_C_VERSION = 202108.00
AWS_IOT_DEVICE_SDK_EMBEDDED_C_SITE = https://github.com/aws/aws-iot-device-sdk-embedded-C
AWS_IOT_DEVICE_SDK_EMBEDDED_C_SITE_METHOD = git
AWS_IOT_DEVICE_SDK_EMBEDDED_C_GIT_SUBMODULES = YES
AWS_IOT_DEVICE_SDK_EMBEDDED_C_LICENSE = MIT
AWS_IOT_DEVICE_SDK_EMBEDDED_C_LICENSE_FILES = LICENSE
AWS_IOT_DEVICE_SDK_EMBEDDED_C_INSTALL_STAGING = YES
AWS_IOT_DEVICE_SDK_EMBEDDED_C_INSTALL_TARGET = NO
AWS_IOT_DEVICE_SDK_EMBEDDED_C_DEPENDENCIES = openssl
AWS_IOT_DEVICE_SDK_EMBEDDED_C_CONF_OPTS = -DBUILD_DEMOS:BOOL=OFF -DBUILD_TESTS:BOOL=OFF -DCSDK_HEADER_INSTALL_PATH="/usr/include/aws" -DCSDK_LIB_INSTALL_PATH="/usr/lib"
AWS_IOT_DEVICE_SDK_EMBEDDED_C_SUPPORTS_IN_SOURCE_BUILD = NO

$(eval $(cmake-package))
