#include <getopt.h>
#include <stdlib.h>

#include "config.h"

static config_option_t config_options = {
    .config = "/etc/fika_iot_gateway/fika_iot_gateway.yaml",

    .redis_server = "127.0.0.1",
    .redis_port = 6379,

    .aws_endpoint = "a1v9khdje2rkn9-ats.iot.us-east-1.amazonaws.com",
    .aws_port = 8883,

    .aws_cert = "/etc/fika_iot_gateway/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-certificate.pem.crt",
    .aws_key = "/etc/fika_iot_gateway/e749408131b357ef9e051f31ffe661540480ff7269fe88f62bc86bc1e4020787-private.pem.key",
    .aws_ca = "/etc/fika_iot_gateway/AmazonRootCA1.pem",
    .aws_thing = "longdongThing1",
};

static int argv_parse(int argc, char **argv)
{
    int c;

    while (1) {
        int option_index = 0;
        struct option long_options[] = {
            {"server",  required_argument, 0, 's'},
            {"port",    required_argument, 0, 'p'},
            {"cert",    required_argument, 0, 'c'},
            {"key",     required_argument, 0, 'k'},
            {"ca",      required_argument, 0, 'a'},
            {"thing",   required_argument, 0, 't'},
            {"endpoint",required_argument, 0, 'e'},
            {"endport", required_argument, 0, 'm'},
            {"help",    no_argument,       0, 'h'},
            {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, ":s:p:c:k:c:t:",
                long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 0:
                printf("option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s", optarg);
                printf("\n");
                break;

            case 's':
                config_options.redis_server = optarg;
                break;
            case 'p':
                config_options.redis_port = atoi(optarg);
                break;
            case 'c':
                config_options.aws_cert = optarg;
                break;
            case 'k':
                config_options.aws_key = optarg;
                break;
            case 'a':
                config_options.aws_ca = optarg;
                break;
            case 't':
                config_options.aws_thing = optarg;
                break;
            case 'e':
                config_options.aws_endpoint = optarg;
                break;
            case 'm':
                config_options.aws_port = atoi(optarg);
                break;

            case '?':
            case 'h':
            default:
                printf("%s [OPTION]... [CONF]\n", argv[0]);
                printf("\t-s, --sert\n\t\tRPC server address\n");
                printf("\t-p, --port\n\t\tRPC server port\n");
                printf("\t-c, --certicate\n\t\tcloud certificate path\n");
                printf("\t-c, --key\n\t\tprivate-key path\n");
                printf("\t-a, --ca\n\t\tcloud Root-CA path\n");
                printf("\t-t, --thing\n\t\tcloud thing name\n");
                return -1;
                break;
        }
    }

    if (optind < argc) {
        config_options.config = argv[optind++];
    }

    return 0;
}

static int config_parse(char *path)
{
    /* TODO */
    return -1;
}

config_option_t *config_init(int argc, char **argv)
{
    int ret;

    ret = argv_parse(argc, argv);
    if (ret == 0) {
        ret = config_parse(config_options.config);
    }

    return &config_options;
}
