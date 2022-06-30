
/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* POSIX includes. */
#include <unistd.h>
#include <time.h>

#include <uv.h>
#include "list.h"
#include "redis_callback.h"
#include "aws_callback.h"
#include "config.h"

static void signal_handler(uv_signal_t *req, int signum)
{
    printf("[info] Signal-%d received!\n", signum);

    printf("TODO clean redis/aws or other\n");

    uv_signal_stop(req);
}

static int config_topic_register(redis_handle_t *redis, aws_handle_t *aws, config_option_t *cfg)
{
    struct list_head *node;
    topic_node_t *topic;
    int ret = 0;

    list_for_each(node, &(cfg->aws_topics)) {
        topic = list_entry(node, topic_node_t, lnode);
        //printf("%s\n", topic->name);
        ret = aws_shadow_subscribe_dynamic(topic->name);

        if (ret < 0) {
            printf("[error] shadow-%s subscribe fail\n", topic->name);
        }
        else {
            printf("[debug] shadow-%s subscribe success\n", topic->name);
        }
    }

    return ret;
}

int main( int argc,
        char ** argv )
{
    int ret = 1;
    uv_loop_t *loop = uv_default_loop();
    uv_idle_t idler;
    uv_signal_t sig;

    srand(time(0));
    config_option_t *cfg = config_init(argc, argv);

    redis_handle_t *redis_hdp = redis_init(loop,
            cfg->redis_server, cfg->redis_port);
    aws_handle_t *aws_hdp = aws_init(loop, (void *)cfg);

    config_topic_register(redis_hdp, aws_hdp, cfg);

    /* TODO fake but need completed */
    aws_subscribe_register(aws_hdp, redis_publish, redis_hdp, NULL);
    redis_subscribe_register(redis_hdp, aws_publish, aws_hdp, NULL);

    uv_signal_init(loop, &sig);
    uv_signal_start(&sig, signal_handler, SIGINT);

    uv_run(loop, UV_RUN_DEFAULT);
    ret = 0;
    return ret;
}
