#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>

#include <yaml.h>

#include "list.h"
#include "config.h"

#define VERSION "0.0.1"

//#define DEBUG   1
#ifdef DEBUG
#define dprintf(fmt, ...) do {          \
    printf(fmt, ##__VA_ARGS__);         \
} while (0)
#else
#define dprintf(fmt, ...)
#endif

#define eprintf(fmt, ...) do {          \
    fprintf(stderr, fmt, ##__VA_ARGS__);\
} while (0)

static config_option_t config_options;

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
            {"version", no_argument,       0, 'v'},
            {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, ":s:p:c:k:c:t:",
                long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 0:
                dprintf("option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s", optarg);
                printf("\n");
                break;

            case 's':
                strcpy(config_options.redis_server, optarg);
                break;
            case 'p':
                config_options.redis_port = atoi(optarg);
                break;
            case 'c':
                strcpy(config_options.aws_cert, optarg);
                break;
            case 'k':
                strcpy(config_options.aws_key, optarg);
                break;
            case 'a':
                strcpy(config_options.aws_ca, optarg);
                break;
            case 't':
                strcpy(config_options.aws_thing, optarg);
                break;
            case 'e':
                strcpy(config_options.aws_endpoint, optarg);
                break;
            case 'm':
                config_options.aws_port = atoi(optarg);
                break;
            case 'v':
                printf("%s %s\n", argv[0], VERSION);
                exit(0);
                break;
            case '?':
            case 'h':
            default:
                printf("%s [OPTION]... [CONF.yaml]\n", argv[0]);
                printf("\t-s, --sert\n\t\tRPC server address\n");
                printf("\t-p, --port\n\t\tRPC server port\n");
                printf("\t-c, --certicate\n\t\tcloud certificate path\n");
                printf("\t-c, --key\n\t\tprivate-key path\n");
                printf("\t-a, --ca\n\t\tcloud Root-CA path\n");
                printf("\t-t, --thing\n\t\tcloud thing name\n");
                printf("\t-v, --version\n\t\tshow version\n");
                exit(1);
                break;
        }
    }

    if (optind < argc) {
        config_options.config = argv[optind++];
    }

    return 0;
}

typedef int (*operator_cb)(void *dst, void *src);

static int operator_atoi(void *dst, void *src)
{
    if (!(dst && src))
        return -1;

    *((int *)dst) = atoi((char *)src);
    return 0;
}

static int operator_strcpy(void *dst, void *src)
{
    if (!(dst && src))
        return -1;

    strcpy(dst, src);
    return 0;
}

typedef int (*parse_cb)(char *, void *next_cb, operator_cb *op_cb, char **op_dst);

static int parse_redis(char *value, void *next_cb, operator_cb *op_cb, char **op_dst);

static int parse_aws(char *value, void *next_cb, operator_cb *op_cb, char **op_dst)
{
    int ret = 1;
    if (*op_dst && op_cb) {
        ret = (*op_cb)((void *)(*op_dst), (void *)value);
        *op_dst = NULL;
        return ret;
    }
    if (strcmp(value, "endpoint") == 0) {
        *op_dst = config_options.aws_endpoint;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "port") == 0) {
        *op_dst = (char *)&config_options.aws_port;
        *op_cb = operator_atoi;
    }
    else if (strcmp(value, "cert") == 0) {
        *op_dst = (char *)&config_options.aws_cert;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "key") == 0) {
        *op_dst = (char *)&config_options.aws_key;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "ca") == 0) {
        *op_dst = (char *)&config_options.aws_ca;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "thing") == 0) {
        *op_dst = (char *)&config_options.aws_thing;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "topic") == 0) {
        topic_node_t *node = malloc(sizeof(topic_node_t));
        memset(node, 0x0, sizeof(*node));
        list_add(&(node->lnode), &config_options.aws_topics);
        *op_dst = node->name;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "redis") == 0) {
        *((parse_cb *)next_cb) = parse_redis;
    }
    else {
        return -1;
    }
    return 0;
}

static int parse_redis(char *value, void *next_cb, operator_cb *op_cb, char **op_dst)
{
    int ret = 1;
    if (*op_dst && op_cb) {
        ret = (*op_cb)((void *)(*op_dst), (void *)value);
        *op_dst = NULL;
        return ret;
    }
    if (strcmp(value, "server") == 0) {
        *op_dst = config_options.redis_server;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "port") == 0) {
        *op_dst = (char *)&config_options.redis_port;
        *op_cb = operator_atoi;
    }
    else if (strcmp(value, "topic") == 0) {
        topic_node_t *node = malloc(sizeof(topic_node_t));
        memset(node, 0x0, sizeof(*node));
        list_add(&(node->lnode), &config_options.redis_topics);
        *op_dst = node->name;
        *op_cb = operator_strcpy;
    }
    else if (strcmp(value, "aws") == 0) {
        *((parse_cb *)next_cb) = parse_aws;
    }
    else {
        return -1;
    }
    return 0;
}

static int parse_init(char *value, void *next_cb, operator_cb *op_cb, char **op_dst)
{
    if (strcmp(value, "redis") == 0) {
        *((parse_cb *)next_cb) = parse_redis;
    }
    else if (strcmp(value, "aws") == 0) {
        *((parse_cb *)next_cb) = parse_aws;
    }
    else {
        return -1;
    }
    return 0;
}

static int config_parse(char *path)
{
    parse_cb parse_runner = parse_init;
    operator_cb operator_runner = operator_strcpy;
    char *op_dst = NULL;

    FILE *fh = fopen(path, "r");
    yaml_parser_t parser;
    yaml_event_t event;   /* New variable */

    /* Initialize parser */
    if(!yaml_parser_initialize(&parser)) {
        eprintf("Failed to initialize parser!\n");
        return -1;
    }
    if(fh == NULL) {
        eprintf("Failed to open file!\n");
        return -1;
    }

    /* Set input file */
    yaml_parser_set_input_file(&parser, fh);

    /* START new code */
    do {
        if (!yaml_parser_parse(&parser, &event)) {
            eprintf("Parser error %d\n", parser.error);
            return -1;
        }

        switch(event.type)
        {
            case YAML_NO_EVENT:
                dprintf("No event!\n");
                break;
            case YAML_STREAM_START_EVENT:
                dprintf("STREAM START\n");
                break;
            case YAML_STREAM_END_EVENT:
                dprintf("STREAM END\n");
                break;
            case YAML_DOCUMENT_START_EVENT:
                dprintf("<b>Start Document</b>\n");
                break;
            case YAML_DOCUMENT_END_EVENT:
                dprintf("<b>End Document</b>\n");
                break;
            case YAML_SEQUENCE_START_EVENT:
                dprintf("<b>Start Sequence</b>\n");
                break;
            case YAML_SEQUENCE_END_EVENT:
                dprintf("<b>End Sequence</b>\n");
                break;
            case YAML_MAPPING_START_EVENT:
                dprintf("<b>Start Mapping</b>\n");
                break;
            case YAML_MAPPING_END_EVENT:
                dprintf("<b>End Mapping</b>\n");
                break;
            case YAML_ALIAS_EVENT:
                dprintf("Got alias (anchor %s)\n", event.data.alias.anchor);
                break;
            case YAML_SCALAR_EVENT:
                dprintf("Got scalar (value %s)\n", event.data.scalar.value);
                parse_runner((char *)event.data.scalar.value,
                        (void *)&parse_runner,
                        &operator_runner,
                        &op_dst);

                break;
        }

        if(event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    } while(event.type != YAML_STREAM_END_EVENT);

    yaml_event_delete(&event);

    /* Cleanup */
    yaml_parser_delete(&parser);
    fclose(fh);
    return 0;
}

config_option_t *config_init(int argc, char **argv)
{
    int ret;

    INIT_LIST_HEAD(&config_options.redis_topics);
    INIT_LIST_HEAD(&config_options.aws_topics);

    ret = argv_parse(argc, argv);
    if (ret == 0) {
        ret = config_parse(config_options.config);
    }

    return &config_options;
}

#ifdef TEST_X86
static void config_dump(void)
{
    struct list_head *node;
    topic_node_t *topic;

    printf("redis:\n");
    printf("\tserver: %s\n", config_options.redis_server);
    printf("\tport: %d\n", config_options.redis_port);
    printf("\ttopic: ");
    list_for_each(node, &config_options.redis_topics) {
        topic = list_entry(node, topic_node_t, lnode);
        printf("%s, ", topic->name);
    }
    printf("\n");

    printf("aws:\n");
    printf("\tendpoint: %s\n", config_options.aws_endpoint);
    printf("\tport: %d\n", config_options.aws_port);
    printf("\tkey: %s\n", config_options.aws_key);
    printf("\tcert: %s\n", config_options.aws_cert);
    printf("\tca: %s\n", config_options.aws_ca);
    printf("\tthing: %s\n", config_options.aws_thing);
    printf("\ttopic: ");
    list_for_each(node, &config_options.aws_topics) {
        topic = list_entry(node, topic_node_t, lnode);
        printf("%s, ", topic->name);
    }
    printf("\n");
    return;
}

int main(int argc, char **argv)
{
    config_init(argc, argv);
    config_dump();

    return 0;
}
#endif
