
/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* POSIX includes. */
#include <unistd.h>

#include <uv.h>
#include "redis_callback.h"
#include "aws_callback.h"

typedef struct {
    char *redis_server;
    int redis_port;

    char *aws_key;
    char *aws_cert;
    char *aws_thing;
} argv_handle_t;

argv_handle_t priv_argv_hdr;

argv_handle_t *argv_parse(int argc, char **argv)
{
    priv_argv_hdr.redis_server = "127.0.0.1";
    priv_argv_hdr.redis_port = 6379;

    priv_argv_hdr.aws_cert = "/etc/fika_iot_gateway/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-certificate.pem.crt";
    priv_argv_hdr.aws_key = "/etc/fika_iot_gateway/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-private.pem.key";
    priv_argv_hdr.aws_thing = "longdongThing1";

    return &priv_argv_hdr;
}

int main( int argc,
        char ** argv )
{
    int ret = 1;
    uv_loop_t *loop = uv_default_loop();
    uv_idle_t idler;

    argv_handle_t *argv_hdp = argv_parse(argc, argv);

    redis_handle_t *redis_hdp = redis_init(loop,
            argv_hdp->redis_server, argv_hdp->redis_port);
    aws_handle_t *aws_hdp = aws_init(loop,
            argv_hdp->aws_key, argv_hdp->aws_cert, argv_hdp->aws_thing);

    aws_subscribe_register(aws_hdp, redis_publish, redis_hdp, NULL);
    redis_subscribe_register(redis_hdp, aws_publish, aws_hdp, NULL);

    uv_run(loop, UV_RUN_DEFAULT);
    ret = 0;
    return ret;
}
