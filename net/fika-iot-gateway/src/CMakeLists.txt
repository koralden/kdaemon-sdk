cmake_minimum_required(VERSION 3.16)

project("fika-iot-gateway")
set( PROJECT_NAME "fika_iot_gateway" )

file( GLOB CURRENT_SRCS "*.c*" )

add_executable(
    ${PROJECT_NAME}
        ${CURRENT_SRCS}
)

#TODO, static not work
#set(OPENSSL_USE_STATIC_LIBS TRUE)
#set(BUILD_SHARED_LIBS OFF)
#set(CMAKE_EXE_LINKER_FLAGS "-static")

#target_link_libraries(
#    ${PROJECT_NAME}
#    PRIVATE
#        ${SDK_DIR}/lib/libaws_iot_backoff_algorithm.a
#        ${SDK_DIR}/lib/libaws_iot_json.a
#        ${SDK_DIR}/lib/libaws_iot_mqtt.a
#        ${SDK_DIR}/lib/libaws_iot_shadow.a
#        ${SDK_DIR}/lib/libclock_posix.a
#        ${SDK_DIR}/lib/libopenssl_posix.a
#        ${SDK_DIR}/lib/libsockets_posix.a
#        ${SDK_DIR}/lib/libuv_a.a
#        ${SDK_DIR}/lib/libhiredis_static.a
#        OpenSSL::SSL
#)

find_package(OpenSSL REQUIRED)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        aws_iot_shadow
        aws_iot_json
        aws_iot_mqtt
        aws_iot_backoff_algorithm
        clock_posix
        openssl_posix
        hiredis
        uv
        OpenSSL::SSL
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
