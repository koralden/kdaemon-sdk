/*
 * AWS IoT Device SDK for Embedded C 202108.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* POSIX includes. */
#include <unistd.h>

#include <uv.h>

/* Shadow config include. */
#include "shadow_config.h"

/* SHADOW API header. */
#include <aws/shadow.h>

/* JSON API header. */
#include <aws/core_json.h>

/* Clock for timer. */
#include <aws/clock.h>

/* shadow demo helpers header. */
#include "helpers.h"
#include "aws_callback.h"
#include "redis_callback.h"
#include "list.h"

#define SHADOW_TOPIC_MAX_LENGTH  ( 256U )

/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef SHADOW_MAX_DEMO_LOOP_COUNT
    #define SHADOW_MAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S           ( 5 )

/**
 * @brief JSON key for response code that indicates the type of error in
 * the error document received on topic `/delete/rejected`.
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY           "code"

/**
 * @brief Length of #SHADOW_DELETE_REJECTED_ERROR_CODE_KEY
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH    ( ( uint16_t ) ( sizeof( SHADOW_DELETE_REJECTED_ERROR_CODE_KEY ) - 1 ) )

/*-----------------------------------------------------------*/

/**
 * @brief The simulated device current power on state.
 */
static uint32_t currentPowerOnState = 0;

/**
 * @brief The flag to indicate the device current power on state changed.
 */
static bool stateChanged = false;

/**
 * @brief When we send an update to the device shadow, and if we care about
 * the response from cloud (accepted/rejected), remember the clientToken and
 * use it to match with the response.
 */
static uint32_t clientToken = 0U;

/**
 * @brief Indicator that an error occurred during the MQTT event callback. If an
 * error occurred during the MQTT event callback, then the demo has failed.
 */
static bool eventCallbackError = false;

/**
 * @brief Status of the response of Shadow delete operation from AWS IoT
 * message broker.
 */
static bool deleteResponseReceived = false;

/**
 * @brief Status of the Shadow delete operation.
 *
 * The Shadow delete status will be updated by the incoming publishes on the
 * MQTT topics for delete acknowledgement from AWS IoT message broker
 * (accepted/rejected). Shadow document is considered to be deleted if an
 * incoming publish is received on `/delete/accepted` topic or an incoming
 * publish is received on `/delete/rejected` topic with error code 404. Code 404
 * indicates that the Shadow document does not exist for the Thing yet.
 */
static bool shadowDeleted = false;

/*-----------------------------------------------------------*/

/**
 * @brief This example uses the MQTT library of the AWS IoT Device SDK for
 * Embedded C. This is the prototype of the callback function defined by
 * that library. It will be invoked whenever the MQTT library receives an
 * incoming message.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pDeserializedInfo Deserialized information from the incoming packet.
 */
static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Process payload from /update/delta topic.
 *
 * This handler examines the version number and the powerOn state. If powerOn
 * state has changed, it sets a flag for the main function to take further actions.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void updateDeltaHandler( MQTTPublishInfo_t * pPublishInfo,
        const char *shadow, uint8_t shadow_len);

/**
 * @brief Process payload from /update/accepted topic.
 *
 * This handler examines the accepted message that carries the same clientToken
 * as sent before.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void updateAcceptedHandler( MQTTPublishInfo_t * pPublishInfo,
        const char *shadow, uint8_t shadow_len);

/**
 * @brief Process payload from `/delete/rejected` topic.
 *
 * This handler examines the rejected message to look for the reject reason code.
 * If the reject reason code is `404`, an attempt was made to delete a shadow
 * document which was not present yet. This is considered to be success for this
 * demo application.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void deleteRejectedHandler( MQTTPublishInfo_t * pPublishInfo );

/*-----------------------------------------------------------*/

static void deleteRejectedHandler( MQTTPublishInfo_t * pPublishInfo )
{
    JSONStatus_t result = JSONSuccess;
    char * pOutValue = NULL;
    uint32_t outValueLength = 0U;
    long errorCode = 0L;

    LogInfo( ( "/delete/rejected json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *    "code": error-code,
     *    "message": "error-message",
     *    "timestamp": timestamp,
     *    "clientToken": "token"
     * }
     */

    /* Then we start to get the version value by JSON keyword "version". */
    result = JSON_Search( ( char * ) pPublishInfo->pPayload,
            pPublishInfo->payloadLength,
            SHADOW_DELETE_REJECTED_ERROR_CODE_KEY,
            SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH,
            &pOutValue,
            ( size_t * ) &outValueLength );

    if( result == JSONSuccess )
    {
        LogInfo( ( "Error code is: %.*s.",
                   outValueLength,
                   pOutValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        errorCode = strtoul( pOutValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No error code in json document!!" ) );
    }

    LogInfo( ( "Error code:%ld.", errorCode ) );

    /* Mark Shadow delete operation as a success if error code is 404. */
    if( errorCode == 404UL )
    {
        shadowDeleted = true;
    }
}

/*-----------------------------------------------------------*/

static void updateDeltaHandler( MQTTPublishInfo_t * pPublishInfo,
        const char *shadow, uint8_t shadow_len)
{
    static uint32_t currentVersion = 0; /* Remember the latestVersion # we've ever received */
    uint32_t version = 0U;
    uint32_t newState = 0U;
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    JSONStatus_t result = JSONSuccess;

    LogInfo( ( "/update/delta json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *      "version": 12,
     *      "timestamp": 1595437367,
     *      "state": {
     *          "powerOn": 1
     *      },
     *      "metadata": {
     *          "powerOn": {
     *          "timestamp": 1595437367
     *          }
     *      },
     *      "clientToken": "388062"
     *  }
     */

    /* Then we start to get the version value by JSON keyword "version". */
    result = JSON_Search( ( char * ) pPublishInfo->pPayload,
            pPublishInfo->payloadLength,
            "version",
            sizeof( "version" ) - 1,
            &outValue,
            ( size_t * ) &outValueLength );

    if( result == JSONSuccess )
    {
        LogInfo( ( "version: %.*s",
                   outValueLength,
                   outValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        version = ( uint32_t ) strtoul( outValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No version in json document!!" ) );
    }

    result = JSON_Search( ( char * ) pPublishInfo->pPayload,
            pPublishInfo->payloadLength,
            "state",
            sizeof( "state" ) - 1,
            &outValue,
            ( size_t * ) &outValueLength );

    if( result == JSONSuccess )
    {
        /*LogInfo( ( "try PUBLISH %.*s %.*s",
                    shadow_len, shadow, 
                    outValueLength, outValue ) );*/

        redis_publish_shadow_message("state",
                shadow, shadow_len,
                outValue, outValueLength);
    }
    else
    {
        LogError( ( "No state in json document!!" ) );
    }
}

/*-----------------------------------------------------------*/

static void updateAcceptedHandler( MQTTPublishInfo_t * pPublishInfo,
        const char *shadow, uint8_t shadow_len)
{
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    uint32_t receivedToken = 0U;
    JSONStatus_t result = JSONSuccess;

    LogInfo( ( "/update/accepted json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* Handle the reported state with state change in /update/accepted topic.
     * Thus we will retrieve the client token from the json document to see if
     * it's the same one we sent with reported state on the /update topic.
     * The payload will look similar to this:
     *  {
     *      "state": {
     *          "reported": {
     *          "powerOn": 1
     *          }
     *      },
     *      "metadata": {
     *          "reported": {
     *          "powerOn": {
     *              "timestamp": 1596573647
     *          }
     *          }
     *      },
     *      "version": 14698,
     *      "timestamp": 1596573647,
     *      "clientToken": "022485"
     *  }
     */

    /* Get clientToken from json documents. */
    result = JSON_Search( ( char * ) pPublishInfo->pPayload,
            pPublishInfo->payloadLength,
            "clientToken",
            sizeof( "clientToken" ) - 1,
            &outValue,
            ( size_t * ) &outValueLength );

    if( result == JSONSuccess )
    {
        LogInfo( ( "clientToken: %.*s", outValueLength,
                   outValue ) );

        /* Convert the code to an unsigned integer value. */
        receivedToken = ( uint32_t ) strtoul( outValue, NULL, 10 );

        LogInfo( ( "receivedToken:%d, clientToken:%u \r\n", receivedToken, clientToken ) );

        /* If the clientToken in this update/accepted message matches the one we
         * published before, it means the device shadow has accepted our latest
         * reported state. We are done. */
        if( receivedToken == clientToken )
        {
            LogInfo( ( "Received response from the device shadow. Previously published "
                       "update with clientToken=%u has been accepted. ", clientToken ) );
        }
        else
        {
            LogWarn( ( "The received clientToken=%u is not identical with the one=%u we sent "
                       , receivedToken, clientToken ) );
        }
    }
    else
    {
        LogError( ( "No clientToken in json document!!" ) );
        eventCallbackError = true;
    }
}

/*-----------------------------------------------------------*/

/* This is the callback function invoked by the MQTT stack when it receives
 * incoming messages. This function demonstrates how to use the Shadow_MatchTopicString
 * function to determine whether the incoming message is a device shadow message
 * or not. If it is, it handles the message depending on the message type.
 */
static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
    const char * pThingName = NULL;
    uint8_t thingNameLength = 0U;
    const char * pShadowName = NULL;
    uint8_t shadowNameLength = 0U;
    uint16_t packetIdentifier;

    ( void ) pMqttContext;

    assert( pDeserializedInfo != NULL );
    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );

    packetIdentifier = pDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        LogInfo( ( "pPublishInfo->pTopicName:%s.", pDeserializedInfo->pPublishInfo->pTopicName ) );

        /* Let the Device Shadow library tell us whether this is a device shadow message. */
        if( SHADOW_SUCCESS == Shadow_MatchTopicString(
                    pDeserializedInfo->pPublishInfo->pTopicName,
                    pDeserializedInfo->pPublishInfo->topicNameLength,
                    &messageType,
                    &pThingName,
                    &thingNameLength,
                    &pShadowName,
                    &shadowNameLength ) )
        {
            MQTTPublishInfo_t *pPublishInfo = pDeserializedInfo->pPublishInfo;
            JSONStatus_t result;
            char *rtype;

            if (!(pPublishInfo && pPublishInfo->pPayload
                        && pPublishInfo->payloadLength)) {
                LogError( ( "The topic public info/payload is invalid!!" ) );
                return;
            }

            /* Make sure the payload is a valid json document. */
            result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                    pPublishInfo->payloadLength );

            if( result != JSONSuccess ) {
                LogError( ( "The json document is invalid!!" ) );
                return;
            }

            LogDebug( ( "eventCallback: %u/%s/%s/%s[%u]",
                        messageType, pThingName, pShadowName,
                        pPublishInfo->pPayload, pPublishInfo->payloadLength) );

            /* Upon successful return, the messageType has been filled in. */
            switch (messageType) {
                case ShadowMessageTypeGetAccepted:
                    {
                        rtype = "get/accepted";
                    }
                    break;
                case ShadowMessageTypeGetRejected:
                    {
                        rtype = "get/rejected";
                    }
                    break;
                case ShadowMessageTypeDeleteAccepted:
                    {
                        LogInfo( ( "Received an MQTT incoming publish on /delete/accepted topic." ) );
                        shadowDeleted = true;
                        deleteResponseReceived = true;
                        rtype = "delete/accepted";
                    }
                    break;
                case ShadowMessageTypeDeleteRejected:
                    {
                        /* Handler function to process payload. */
                        deleteRejectedHandler( pPublishInfo );
                        deleteResponseReceived = true;
                        rtype = "delete/rejected";
                    }
                    break;
                case ShadowMessageTypeUpdateAccepted:
                    {
                        /* Handler function to process payload. */
                        updateAcceptedHandler( pPublishInfo,
                                pShadowName, shadowNameLength );
                        rtype = "update/accepted";
                    }
                    break;
                case ShadowMessageTypeUpdateRejected:
                    {
                        LogInfo( ( "/update/rejected json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );
                        rtype = "update/rejected";
                    }
                    break;
                case ShadowMessageTypeUpdateDocuments:
                    {
                        LogInfo( ( "/update/documents json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );
                        rtype = "update/document";
                    }
                    break;
                case ShadowMessageTypeUpdateDelta:
                    {
                        /* Handler function to process payload. */
                        updateDeltaHandler( pPublishInfo,
                                pShadowName, shadowNameLength );
                        rtype = "update/delta";
                    }
                    break;
                default:
                    {
                        LogInfo( ( "Other message type:%d !!", messageType ) );
                        rtype = NULL;
                    }
            }

            if (rtype != NULL) {
                redis_publish_shadow_message(rtype,
                        pShadowName, shadowNameLength,
                        pPublishInfo->pPayload, pPublishInfo->payloadLength);
            }

        }
        else
        {
            LogError( ( "Shadow_MatchTopicString parse failed:%s !!", ( const char * ) pDeserializedInfo->pPublishInfo->pTopicName ) );
            eventCallbackError = true;
        }
    }
    else
    {
        HandleOtherIncomingPacket( pPacketInfo, packetIdentifier );
    }
}

/*-----------------------------------------------------------*/

static ShadowStatus_t xxxx( ShadowTopicStringType_t topicType,
        const char * pThingName,
        uint8_t thingNameLength,
        const char * pShadowName,
        uint8_t shadowNameLength,
        const char * pTopicBuffer,
        const uint16_t * pOutLength )
{
    ShadowStatus_t shadowStatus = SHADOW_BAD_PARAMETER;

    if( ( pTopicBuffer == NULL ) ||
            ( pThingName == NULL ) ||
            ( thingNameLength == 0U ) ||
            ( ( pShadowName == NULL ) && ( shadowNameLength > 0U ) ) ||
            ( topicType >= ShadowTopicStringTypeMaxNum ) ||
            ( pOutLength == NULL ) )
    {
        LogError( ( "Invalid input parameters pTopicBuffer: %p, pThingName: %p, thingNameLength: %u,\
                    pShadowName: %p, shadowNameLength: %u, topicType: %d, pOutLength: %p.",
                    ( void * ) pTopicBuffer,
                    ( void * ) pThingName,
                    ( unsigned int ) thingNameLength,
                    ( void * ) pShadowName,
                    ( unsigned int ) shadowNameLength,
                    ( int ) topicType,
                    ( void * ) pOutLength ) );
    }
}


static aws_handle_t priv_aws_hdr;

/*static int classic_topic_subscribe(void)
{
    int ret = -1;
    ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
    char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
    uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
    uint16_t outLength = 0;

    shadowStatus = xxxx(ShadowTopicStringTypeUpdateDelta,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            NULL, 0,
            topicBuffer, &outLength);

    shadowStatus = Shadow_AssembleTopicString(ShadowTopicStringTypeUpdateDelta,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            NULL, 0,
            topicBuffer, bufferSize,
            &outLength);

    if (shadowStatus == SHADOW_SUCCESS) {
        ret = aws_topic_subscribe(topicBuffer, outLength);
    }
    else {
        LogError( ( "classic_topic_subscribe(%s) update/delta fail...%u",
                    SHADOW_NAME_CLASSIC, shadowStatus) );
    }
    return ret;
}*/

static int iot_init(void *vcfg)
{
    int ret;

    ret = aws_mqtt_establish(eventCallback, vcfg);
    if (ret == EXIT_FAILURE) {
        /* Log error to indicate connection failure. */
        LogError( ( "Failed to connect to MQTT broker." ) );
        return -1;
    }

    //ret = classic_topic_subscribe();

    return 0;
}

typedef struct {
    uv_idle_t p_idle;
#ifdef CONFIG_SELF_TEST
    uv_timer_t p_timer;
#endif

    int status;
    void *extra;
    uint64_t timer_cnt;
    int fail_cnt;
    int init_cnt;
    int delay_time;
} fika_idle_t;

#ifdef CONFIG_SELF_TEST
#define IOT_TIMER_LOOP_MS       600002
static void iot_timer_loop(uv_timer_t *timer)
{
    /*TODO, hard code for test only */
    fika_idle_t *idle = container_of(timer, fika_idle_t, p_timer);
    static int first = 1;

    if (first == 1) {
        aws_publish_shadow_update("provision",
                "{\"sdk-version\":\"0.01.00\",\"ap-wallet-address\":\"not-real\"}");
        first = 0;
    }
    else {
        char payload[128];
        int err;
        double uptime;

        uv_sleep(rand() % 5000);
        err = uv_uptime(&uptime);
        if (err != 0) {
            uptime = 0;
        }

        err = snprintf(payload, sizeof(payload) - 1,
                "{\"up-time\":\"%f\",\"latency\":30}",
                uptime);
        if (err > 0) {
            payload[err + 1] = '\0';
            aws_publish_shadow_update("heartbeat", payload);
        }
    }
    idle->timer_cnt++;

    return;
}
#endif

static void process_task(uv_idle_t *h)
{
    int ret = -1;
    fika_idle_t *idle = (fika_idle_t *)h;

    if (idle->status == 1) {
        ret = aws_process_task(NULL);
    }

    if (ret == 0) {
        if (idle->fail_cnt != 0) {
            idle->fail_cnt = 0;
            idle->timer_cnt = 0;
            idle->init_cnt = 0;
            idle->delay_time = 500;

#ifdef CONFIG_SELF_TEST
            uv_timer_start(&idle->p_timer, iot_timer_loop, 2000, IOT_TIMER_LOOP_MS);
#endif
        }
    }
    else {
        idle->fail_cnt++;

        /* over 1min */
        if (idle->fail_cnt == 120) {

            idle->status = -1;
            idle->fail_cnt = 0;

#ifdef CONFIG_SELF_TEST
            uv_timer_stop(&idle->p_timer);
#endif
            iot_init(idle->extra);

            idle->init_cnt++;
            idle->status = 1;

            idle->delay_time = idle->init_cnt * 500;
            if (idle->delay_time == 10000) {
                idle->delay_time = 100;
            }
        }
    }

    uv_sleep(idle->delay_time);

    return;
}

aws_handle_t *aws_init(void *event_loop, void *vcfg)
{
    uv_loop_t *uv_loop = (uv_loop_t *)event_loop;
    static fika_idle_t idler = {
        .status = -1,
    };
    int ret;

    ret = iot_init(vcfg);

    uv_idle_init(uv_loop, &idler.p_idle);
#ifdef CONFIG_SELF_TEST
    uv_timer_init(uv_loop, &idler.p_timer);
#endif
    idler.init_cnt = 1;
    idler.delay_time = 100;
    idler.status = 1;
    idler.fail_cnt = 1; /* as first time */
    idler.extra = vcfg;
    uv_idle_start(&idler.p_idle, process_task);

    memset(priv_aws_hdr.thing, 0x0, sizeof(priv_aws_hdr.thing));
    /* TODO check length? */
    strcpy(priv_aws_hdr.thing,
            ((config_option_t *)vcfg)->aws_thing);

    return &priv_aws_hdr;
}

int aws_subscribe_register(aws_handle_t *hdp, int (*cb)(void *, void *),
        void *cb_hdp, void *cb_extra)
{
    if (!(hdp && cb && cb_hdp && cb_extra)) {
        return -1;
    }

    /*hdp->cb_publisher = cb;
    hdp->cb_hdp = cb_hdp;
    hdp->cb_extra = cb_extra;*/

    return 0;
}

int aws_publish(void *hdp, void *extra)
{
    /* TODO a*/
    return -1;
}

int aws_shadow_subscribe_assembly(
        ShadowTopicStringType_t stype,
        char *thing, size_t thing_sz,
        char *topic, size_t topic_sz)
{
    int ret = -1;
    ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
    char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
    uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
    uint16_t outLength = 0;

    shadowStatus = Shadow_AssembleTopicString(stype,
            thing, thing_sz, topic, topic_sz,
            topicBuffer, bufferSize,
            &outLength);

    if (shadowStatus == SHADOW_SUCCESS) {
        ret = aws_topic_subscribe(topicBuffer, outLength);
    }
    return ret;
}

int aws_shadow_subscribe_dynamic(char *topic)
{
    int ret;

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeUpdateDelta,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic update/delta fail.") );
    }

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeUpdateAccepted,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic update/accepted fail.") );
    }

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeUpdateRejected,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic update/rejected fail.") );
    }

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeDeleteAccepted,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic delete/accepted fail.") );
    }

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeDeleteRejected,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic delete/rejected fail.") );
    }

    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeGetAccepted,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic delete/rejected fail.") );
    }
    ret = aws_shadow_subscribe_assembly(ShadowTopicStringTypeGetRejected,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic));
    if (ret < 0) {
        LogError( ( "aws_shadow_subscribe_dynamic delete/rejected fail.") );
    }
    return ret;
}

#define SHADOW_JSON_TEMPLATE     \
    "{"                         \
    "\"state\":{"               \
    "\"reported\": %s"           \
    "},"                        \
    "\"clientToken\":\"%06lu\"" \
    "}"

int aws_publish_shadow_update(char *topic, char *value)
{
    int ret = -1;
    ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
    char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
    uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
    uint16_t outLength = 0;

    shadowStatus = Shadow_AssembleTopicString(ShadowTopicStringTypeUpdate,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, strlen(topic),
            topicBuffer, bufferSize,
            &outLength);

    if (shadowStatus == SHADOW_SUCCESS) {
        static char updateDocument[256];
        ( void ) memset( updateDocument,
                0x00,
                sizeof( updateDocument ) );

        /* Keep the client token in global variable used to compare if
         * the same token in /update/accepted. */
        clientToken = ( Clock_GetTimeMs() % 1000000 );
        //int clientVer = 9;

        int num = snprintf(updateDocument,
                sizeof(updateDocument) - 1,
                SHADOW_JSON_TEMPLATE,
                value,
                ( long unsigned ) clientToken);

        ret = aws_topic_publish(topicBuffer, outLength, updateDocument, num);
    }
    else {
        LogError( ( "aws_shadow_subscribe_dynamic fail.") );
    }
    return ret;
}

int json_parse_fetch(char *payload, size_t p_len,
        char *key, size_t k_len,
        char **out_ptr, size_t *out_len)
{
    JSONStatus_t result;

    result = JSON_Validate((const char *)payload, p_len);
    if( result != JSONSuccess ) {
        LogError( ( "The json document is invalid!!" ) );
        return -1;
    }

    result = JSON_Search(payload, p_len, key, k_len,
            out_ptr, out_len);

    return (result == JSONSuccess) ? 0 : -1;
}

int aws_publish_shadow_raw(char *topic, size_t topic_len,
        char *j_payload, size_t j_payload_len)
{
    int ret = -1;
    JSONStatus_t result;
    ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
    char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
    uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
    uint16_t outLength = 0;
    char *type_ptr;
    uint32_t type_len;
    ShadowTopicStringType_t type;
    char *report;
    uint32_t report_len;

    /* topic && topic_len zero for class-shadow */
    if (!(j_payload && j_payload_len))
        return ret;

    ret = json_parse_fetch(j_payload, j_payload_len,
            "type", (( uint16_t )(sizeof("type") - 1)),
            &type_ptr, (size_t *)&type_len);

    if (ret < 0) {
        LogError(("type not found from %.*s",
                    j_payload_len, j_payload));

        return ret;
    }

    type = strtoul(type_ptr, NULL, 10 );
    printf("[debug][%s]: type=%u\n", __func__, type);

    if (type != ShadowTopicStringTypeGet) {
        result = JSON_Search(j_payload, j_payload_len,
                "report", (( uint16_t )(sizeof("report") - 1)),
                &report, (size_t *)&report_len);

        if (result != JSONSuccess) {
            LogError(("report not found from %.*s",
                        j_payload_len, j_payload));

            return -1;
        }

        result = JSON_Validate((const char *)report, report_len);
        if( result != JSONSuccess ) {
            LogError(("report NOT json document %.*s",
                        report_len, report));
            return -1;
        }
    }
    /*printf("[debug][%s]: type/report = %s[%u]/%s[%u]\n",
            __func__,
            type_ptr, type_len,
            report, report_len);

    type = strtoul(type_ptr, NULL, 10 );*/

    shadowStatus = Shadow_AssembleTopicString(type,
            priv_aws_hdr.thing, strlen(priv_aws_hdr.thing),
            topic, topic_len, topicBuffer,
            bufferSize, &outLength);

    if (shadowStatus != SHADOW_SUCCESS) {
        LogError( ( "aws_shadow_subscribe_dynamic fail.") );
        return -1;
    }

    ret = aws_topic_publish(topicBuffer, outLength,
            report, report_len);
    return ret;
}
