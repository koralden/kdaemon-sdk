#ifndef __REDIS_CALLBACK_H__
#define __REDIS_CALLBACK_H__

#include <stdint.h>

typedef struct {
    void *gw;

    int (*cb_publisher)(void *hdp, void *extra);
    void *cb_hdp;
    void *cb_extra;
} redis_handle_t;

redis_handle_t *redis_init(void *event_loop, char *server_ip, int port);
int redis_subscribe_register(redis_handle_t *hdp, int (*cb)(void *, void*),
        void *cb_hdp, void *cb_extra);
int redis_publish(void *hdp, void *extra);
int redis_publish_shadow_message(const char *type,
        const char *shadow, uint8_t shadow_len,
        const char *value, uint32_t value_len);

#endif // __REDIS_CALLBACK_H__
