
/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* POSIX includes. */
#include <unistd.h>

#include <uv.h>
#include "redis_callback.h"
#include "aws_callback.h"
#include "config.h"

int main( int argc,
        char ** argv )
{
    int ret = 1;
    uv_loop_t *loop = uv_default_loop();
    uv_idle_t idler;

    config_option_t *cfg = config_init(argc, argv);

    redis_handle_t *redis_hdp = redis_init(loop,
            cfg->redis_server, cfg->redis_port);
    aws_handle_t *aws_hdp = aws_init(loop, (void *)cfg);

    aws_subscribe_register(aws_hdp, redis_publish, redis_hdp, NULL);
    redis_subscribe_register(redis_hdp, aws_publish, aws_hdp, NULL);

    uv_run(loop, UV_RUN_DEFAULT);
    ret = 0;
    return ret;
}
