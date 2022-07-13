#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libuv.h>

#include "redis_callback.h"
#include "aws_callback.h"

static redis_handle_t priv_redis_hdr;
static redisAsyncContext *gateway;
static uv_async_t async_gateway;

static void async_gateway_update(uv_async_t *handle)
{
    printf("[debug][%s] TODO if need history/confirm via redis\n",
            __func__);
    /*redisAsyncCommand(gateway, NULL, NULL, "LPUSH %s %s",
            "test", "test");*/
    return;
}

static void connectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("connect error: %s\n", c->errstr);
        return;
    }
    printf("Connected...\n");
}

static void disconnectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("disconnect because of error: %s\n", c->errstr);
        return;
    }
    printf("Disconnected...\n");
}

static void shadow_subCallback(redisAsyncContext *c, void *r, void *privdata)
{
    redisReply *reply = r;
    redis_handle_t *hdp = (redis_handle_t *)privdata;

    if (strcmp(reply->element[0]->str,"subscribe") == 0) {
        printf("SUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"unsubscribe") == 0) {
        printf("UNSUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"message") == 0) {
        printf("SUBSCRIBE message %s %s\n",
                reply->element[1]->str,
                reply->element[2]->str);

        int ret = 1;
        //TODO if (hdp && hdp->cb_publisher) {
            //ret = hdp->cb_publisher(hdp->cb_hdp, hdp->cb_extra);
            ret = aws_shadow_subscribe_dynamic(reply->element[2]->str);
        //}
        if (ret >= 0) {
            /*redisAsyncCommand(gateway, NULL, NULL, "LPUSH %s %s",
                    reply->element[1]->str, reply->element[2]->str);*/
            uv_async_send(&async_gateway);
        }
    } else {
    }

    return;
}

static void update_mqtt_callback(redisAsyncContext *c, void *r, void *privdata)
{
    /* TODO */
    return;
}

static void update_shadow_callback(redisAsyncContext *c, void *r, void *privdata)
{
    redisReply *reply = r;
    redis_handle_t *hdp = (redis_handle_t *)privdata;

    if (!(reply && reply->element)) {
        printf("PSUBSCRIBE NULL!!??\n");
        return;
    }

    if (strcmp(reply->element[0]->str,"psubscribe") == 0) {
        printf("PSUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"unpsubscribe") == 0) {
        printf("UNPSUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"pmessage") == 0) {
        printf("PSUBSCRIBE (p)message %s %s %s\n",
                reply->element[1]->str,
                reply->element[2]->str,
                reply->element[3]->str);

        int ret = 1;
        //TODO if (hdp && hdp->cb_publisher) {
            //ret = hdp->cb_publisher(hdp->cb_hdp, hdp->cb_extra);
            char *topic = reply->element[2]->str + strlen("nms.shadow.update.");
            char *value = reply->element[3]->str;
            ret = aws_publish_shadow_update(topic, value);
        //}
        if (ret >= 0) {
            /*redisAsyncCommand(gateway, NULL, NULL, "LPUSH %s %s",
                    reply->element[2]->str, reply->element[3]->str);*/
            uv_async_send(&async_gateway);
        }
    } else {
    }

    return;
}

static void shadow_raw_callback(redisAsyncContext *c, void *r, void *privdata)
{
    redisReply *reply = r;
    redis_handle_t *hdp = (redis_handle_t *)privdata;

    if (!(reply && reply->element)) {
        printf("%s: null reply\n", __func__);
        return;
    }

    if (!(reply->element[0]->str && reply->element[0]->len)) {
        printf("%s: element[0] zero length\n", __func__);
        return;
    }

    if (strcmp(reply->element[0]->str,"psubscribe") == 0) {
        printf("PSUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"unpsubscribe") == 0) {
        printf("UNPSUBSCRIBE %s completed\n", reply->element[1]->str);
    } else if (strcmp(reply->element[0]->str,"pmessage") == 0) {
#define CMP_SHADOW_RAW  "nms.shadow.raw."
        char *topic;
        size_t topic_len;
        char *j_payload;
        size_t j_payload_len;

        if ((reply->element[2]->str == NULL)
                || (reply->element[2]->len <= strlen(CMP_SHADOW_RAW))) {
            printf("%s: CLASSIC-SHADOW due to element[2] zero length\n", __func__);
        }

        if (!(reply->element[3]->str && reply->element[3]->len)) {
            printf("%s: element[3] zero length\n", __func__);
            return;
        }

        printf("PSUBSCRIBE (p)message RAW %s %s %s\n",
                reply->element[1]->str,
                reply->element[2]->str,
                reply->element[3]->str);

        topic = reply->element[2]->str + strlen(CMP_SHADOW_RAW);
        topic_len = reply->element[2]->len - strlen(CMP_SHADOW_RAW);
        j_payload = reply->element[3]->str;
        j_payload_len = reply->element[3]->len;

        printf("[debug][%s]: topic/topic_len/j_payload/j_payload_len = %s/%u/%s/%u\n",
                __func__,
                topic, topic_len, j_payload, j_payload_len);

        if (aws_publish_shadow_raw(topic, topic_len, j_payload, j_payload_len) >= 0) {
            uv_async_send(&async_gateway);
        }
    } else {
        printf("UNKNOWN %s \n", reply->element[0]->str);
    }

    return;
}


static void mqtt_subCallback(redisAsyncContext *c, void *r, void *privdata)
{
    /* TODO */
    shadow_subCallback(c, r, privdata);
}

static void publish_callback(redisAsyncContext *c, void *r, void *privdata) {
    (void)privdata; //unused
    redisReply *reply = r;

    if (reply == NULL) {
        printf("[publish][error]: %s\n", c->errstr ? c->errstr : "unknown error");
        return;
    }
    /* XXX more information/debug if want to trace */
    return;
}

#if 0
void debugCallback(redisAsyncContext *c, void *r, void *privdata) {
    (void)privdata; //unused
    redisReply *reply = r;
    if (reply == NULL) {
        /* The DEBUG SLEEP command will almost always fail, because we have set a 1 second timeout */
        printf("`DEBUG SLEEP` error: %s\n", c->errstr ? c->errstr : "unknown error");
        return;
    }
    /* Disconnect after receiving the reply of DEBUG SLEEP (which will not)*/
    redisAsyncDisconnect(c);
}

void getCallback(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = r;
    if (reply == NULL) {
        printf("`GET key` error: %s\n", c->errstr ? c->errstr : "unknown error");
        return;
    }
    printf("`GET key` result: argv[%s]: %s\n", (char*)privdata, reply->str);

    /* start another request that demonstrate timeout */
    //redisAsyncCommand(c, debugCallback, NULL, "DEBUG SLEEP %f", 1.5);
}

void psubCallback(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = r;

    printf("PSUBSCRIBE %s => %s\n", privdata ? (char*)privdata : "NULL",
            (reply == NULL) ? (c->errstr ? c->errstr : "unknown error") :
            reply->str);
    return;
}

void fake_aws_task(uv_idle_t *h)
{
    fprintf(stderr, "AWS-IOT process....\n");
    //uv_sleep(200);

    return;
}

void setCallback(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = r;

    printf("SET %s => %s\n", "...",
            (reply == NULL) ? (c->errstr ? c->errstr : "unknown error") :
            reply->str);
    return;
}
#endif

redis_handle_t *redis_init(void *event_loop, char *server_ip, int port)
{
    uv_loop_t *uv_loop = (uv_loop_t *)event_loop;

    redisAsyncContext *c = redisAsyncConnect(server_ip, port);
    if (c->err) {
        /* Let *c leak for now... */
        printf("Error: 1111 %s:%d %s\n", server_ip, port, c->errstr);
        return NULL;
    }

    redisLibuvAttach(c, uv_loop);
    redisAsyncSetConnectCallback(c,connectCallback);
    redisAsyncSetDisconnectCallback(c,disconnectCallback);
    redisAsyncSetTimeout(c, (struct timeval){ .tv_sec = 2, .tv_usec = 0});

    gateway = redisAsyncConnect(server_ip, port);
    if (gateway->err) {
        printf("Error: 222 %s:%d %s\n", server_ip, port, c->errstr);
        return NULL;
    }

    redisLibuvAttach(gateway, uv_loop);
    redisAsyncSetConnectCallback(gateway, connectCallback);
    redisAsyncSetDisconnectCallback(gateway, disconnectCallback);
    //redisAsyncSetTimeout(gateway, (struct timeval){ .tv_sec = 2, .tv_usec = 0});
    uv_async_init(uv_loop, &async_gateway, async_gateway_update);

    /* TODO */
    redisAsyncCommand(c, mqtt_subCallback, &priv_redis_hdr,
            "SUBSCRIBE nms.mqtt.subscribe");
    redisAsyncCommand(c, shadow_subCallback, &priv_redis_hdr,
            "SUBSCRIBE nms.shadow.subscribe");

    redisAsyncCommand(c, update_mqtt_callback, NULL,
            "PSUBSCRIBE nms.mqtt.update.*");
    redisAsyncCommand(c, update_shadow_callback, NULL,
            "PSUBSCRIBE nms.shadow.update.*");
    redisAsyncCommand(c, shadow_raw_callback, NULL,
            "PSUBSCRIBE nms.shadow.raw.*");

    redisAsyncCommand(gateway, NULL, NULL, "PUBLISH service.cmp ready");
    redisAsyncCommand(gateway, NULL, NULL, "SET service.cmp ready");

    return &priv_redis_hdr;
}

int redis_subscribe_register(redis_handle_t *hdp, int (*cb)(void *, void*),
        void *cb_hdp, void *cb_extra)
{
    if (!(hdp && cb && cb_hdp && cb_extra)) {
        return -1;
    }

    hdp->cb_publisher = cb;
    hdp->cb_hdp = cb_hdp;
    hdp->cb_extra = cb_extra;

    return 0;
}

int redis_publish(void *hdp, void *extra)
{
    /* TODO */
    return -1;
}

int redis_publish_shadow_message(const char *type,
        const char *shadow, uint8_t shadow_len,
        const char *value, uint32_t value_len)
{
    /*printf("[redis][debug] PUBLISH %.*s '%.*s'\n",
            shadow_len, shadow,
            value_len, value);*/

    char shadow_str[256];
    memset(shadow_str, 0x0, sizeof(shadow_str));
    snprintf(shadow_str, sizeof(shadow_str) - 1, "nms.shadow.%.*s/%s",
            shadow_len, shadow, type);

    /*  pass binary safe strings in a command, the %b specifier can be used.
     *  Together with a pointer to the string, it requires a size_t length
     *  argument of the string
     *  ref: https://github.com/redis/hiredis/#sending-commands
     */
    redisAsyncCommand(gateway, publish_callback, NULL, "PUBLISH %s %b",
            shadow_str, value, value_len);
    return 0;
}

