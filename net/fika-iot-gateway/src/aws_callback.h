#ifndef __AWS_CALLBACK_H__
#define __AWS_CALLBACK_H__

typedef struct {
    void *mqtt_ctx;
    
    char thing[128];
} aws_handle_t;

aws_handle_t *aws_init(void *event_loop, void *vcfg);
int aws_subscribe_register(aws_handle_t *hdp, int (*cb)(void *, void *),
        void *cb_hdp, void *cb_extra);
int aws_publish(void *hdp, void *extra);
int aws_shadow_subscribe_dynamic(char *topic);
int aws_shadow_publish_dynamic(char *topic, char *value);

#endif // __AWS_CALLBACK_H__
