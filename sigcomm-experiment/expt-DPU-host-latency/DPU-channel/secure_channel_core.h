/*
 * Copyright (c) 2021-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SECURE_CHANNEL_CORE_H_
#define SECURE_CHANNEL_CORE_H_

#include <pthread.h>
#include <stdatomic.h>

#include <doca_dev.h>
#include <stdbool.h>
#include <sys/time.h>

#include "comch_utils.h"

enum sc_mode
{
    SC_MODE_HOST, /* Run endpoint in Host */
    SC_MODE_DPU   /* Run endpoint in DPU */
};

struct sc_config
{
    enum sc_mode mode;                                        /* Mode of operation */
    int send_msg_size;                                        /* Message size in bytes */
    int send_msg_nb;                                          /* Number of messages to send */
    char cc_dev_pci_addr[DOCA_DEVINFO_PCI_ADDR_SIZE];         /* Comm Channel DOCA device PCI address */
    char cc_dev_rep_pci_addr[DOCA_DEVINFO_REP_PCI_ADDR_SIZE]; /* Comm Channel DOCA device representor PCI address */
    int n_threads;
};

enum transfer_state
{
    FASTPATH_IDLE,
    FASTPATH_IN_PROGRESS,
    FASTPATH_COMPLETE,
    FASTPATH_ERROR,
};

/* Producer and consumer context (fast_path_ctx) */
struct shared_ctx_data
{
    enum sc_mode mode;
};

struct cc_ctx
{
    struct sc_config *cfg; /* Secure Channel configuration */
    int svr_clt_sync;      // 1: Synchronization done, start event loop
    uint32_t total_msgs;   /* Total messages to send/recv before completing */

    int n_clts; /* Number of client threads */

    struct doca_comch_connection *comch_connection; /* Comm channel for fast path control */
    uint32_t *remote_consumer_ids;                   /* ID of consumer created at the opposite end on comch_connection */
    int remote_consumer_counter;

    atomic_int active_threads; /* Thread safe counter for detached threads */
    struct shared_ctx_data ctx_data;
};

typedef struct
{
    int thread_id;

    struct doca_comch_producer *producer;
    enum transfer_state producer_state; /* State the producer is in */

    struct doca_comch_consumer *consumer;
    enum transfer_state consumer_state; /* State the consumer is in */

    uint32_t peer_consumer_id;
    uint32_t self_consumer_id;

    struct doca_buf *send_doca_buf;

    struct cc_ctx *ctx;
} svr_thread_info_t;

typedef struct {
    long long total_rtt;
    long total_messages;
    float request_rate;

    uint32_t producer_completed_msgs;   /* Current number of messages verified as send/received by producer */
    uint32_t producer_submitted_msgs;   /* Total messages submitted but not verified complete (producer only) */
    uint32_t consumer_completed_msgs;   /* Current number of messages verified as send/received by consumer */
    uint32_t consumer_submitted_msgs;   /* Total messages submitted but not verified complete (consumer only) */

    struct timeval start_time;         /* Start time of send/recv */
    struct timeval end_time;           /* End   time of send/recv */

} client_thread_data_t;

typedef struct
{
    pthread_t clt_t; /* Client thread */
    int thread_id;
    client_thread_data_t clt_thread_data;

    struct doca_comch_producer *producer;
    enum transfer_state producer_state; /* State the producer is in */

    struct doca_comch_consumer *consumer;
    enum transfer_state consumer_state; /* State the consumer is in */

    uint32_t peer_consumer_id;
    uint32_t self_consumer_id;

    struct doca_buf *send_doca_buf;

    struct cc_ctx *ctx; /* CC context shared among client threads */
} clt_thread_info_t;

enum msg_type
{
    START_MSG, /* Metadata contains information on number of messages */
    END_MSG,   /* Opposite side has completed processing */
};

/* Initial message sent from both sides to configure the opposite end */
struct metadata_msg
{
    enum msg_type type; /* Indicates the type of message sent */
};

/*
 * Starts Comch Producer-Consumer Ring Microbenchmark
 *
 * @comch_cfg [in]: Comch configuration structure
 * @cfg [in]: App configuration structure
 * @ctx [in]: Threads context structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t comch_producer_consumer_start(struct comch_cfg *comch_cfg, struct sc_config *cfg, struct cc_ctx *ctx);

/*
 * Registers Secure Channel parameters
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_secure_channel_params(void);

/*
 * Callback event for messages on the comch
 *
 * In this app the same callback is used for both client and server
 *
 * @event [in]: message receive event
 * @recv_buffer [in]: array of bytes containing the message data
 * @msg_len [in]: number of bytes in the recv_buffer
 * @comch_connection [in]: comm channel connection over which the event occurred
 */
void comch_recv_event_cb(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer, uint32_t msg_len,
                         struct doca_comch_connection *comch_connection);

/*
 * Callback event for new consumers on the comch
 *
 * @event [in]: consumer event
 * @comch_connection [in]: control channel connection associated with the new consumer
 * @id [in]: id of the consumer (unique to the comch_connection)
 */
void new_consumer_callback(struct doca_comch_event_consumer *event, struct doca_comch_connection *comch_connection,
                           uint32_t id);

/*
 * Callback event for expired consumers on the comch
 *
 * @event [in]: consumer event
 * @comch_connection [in]: control channel connection associated with the expired consumer
 * @id [in]: id of the consumer (unique to the comch_connection)
 */
void expired_consumer_callback(struct doca_comch_event_consumer *event, struct doca_comch_connection *comch_connection,
                               uint32_t id);

#endif /* SECURE_CHANNEL_CORE_H_ */
