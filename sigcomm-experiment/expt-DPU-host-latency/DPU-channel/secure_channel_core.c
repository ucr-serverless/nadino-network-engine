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

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_comch_consumer.h>
#include <doca_comch_producer.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>

#include <common_doca.h>

#include <time.h>
#include <utils_doca.h>

#include "comch_ctrl_path_common.h"
#include "doca_types.h"
#include "secure_channel_core.h"

#define MAX_MSG_SIZE 65535         /* Max message size */
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the connection every 10 microseconds  */
#define MAX_FASTPATH_TASKS 1024    /* Maximum number of producer/consumer tasks to use */
#define CACHE_ALIGN 64             /* Cache line alignment for producer/consumer performance */

#define NS_PER_SEC 1E9  /* Nano-seconds per second */
#define NS_PER_MSEC 1E6 /* Nano-seconds per millisecond */

#define DEFAULT_CLIENT_THREADS 4
uint32_t num_client_threads = DEFAULT_CLIENT_THREADS;

DOCA_LOG_REGISTER(SECURE_CHANNEL::Core);

/* Local memory data for preparing and allocating doca_bufs */
struct local_memory_bufs
{
    struct doca_dev *dev;           /* device associated with memory */
    struct doca_mmap *mmap;         /* mmap for registered memory */
    struct doca_buf_inventory *inv; /* inventory to assign doca_bufs */
    char *buf_data;                 /* allocated data to reference in bufs */
};

/* ARGP Callback - Handle messages number parameter */
static doca_error_t messages_number_callback(void *param, void *config)
{
    struct sc_config *app_cfg = (struct sc_config *)config;
    int nb_send_msg = *(int *)param;

    if (nb_send_msg < 1)
    {
        DOCA_LOG_ERR("Amount of messages to be sent by the client is less than 1");
        return DOCA_ERROR_INVALID_VALUE;
    }

    app_cfg->send_msg_nb = nb_send_msg;

    return DOCA_SUCCESS;
}

/* ARGP Callback - Handle message size parameter */
static doca_error_t message_size_callback(void *param, void *config)
{
    struct sc_config *app_cfg = (struct sc_config *)config;
    int send_msg_size = *(int *)param;

    if (send_msg_size < 1 || send_msg_size > MAX_MSG_SIZE)
    {
        DOCA_LOG_ERR("Received message size is not supported. Max is %u", MAX_MSG_SIZE);
        return DOCA_ERROR_INVALID_VALUE;
    }

    app_cfg->send_msg_size = send_msg_size;
    return DOCA_SUCCESS;
}

/* ARGP Callback - Handle Comm Channel DOCA device PCI address parameter */
static doca_error_t dev_pci_addr_callback(void *param, void *config)
{
    struct sc_config *cfg = (struct sc_config *)config;
    const char *dev_pci_addr = (char *)param;

    if (strnlen(dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE) == DOCA_DEVINFO_PCI_ADDR_SIZE)
    {
        DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

    strlcpy(cfg->cc_dev_pci_addr, dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE);

    return DOCA_SUCCESS;
}

/* ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter */
static doca_error_t rep_pci_addr_callback(void *param, void *config)
{
    struct sc_config *cfg = (struct sc_config *)config;
    const char *rep_pci_addr = (char *)param;

    if (cfg->mode == SC_MODE_DPU)
    {
        if (strnlen(rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE) == DOCA_DEVINFO_REP_PCI_ADDR_SIZE)
        {
            DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
                         DOCA_DEVINFO_REP_PCI_ADDR_SIZE - 1);
            return DOCA_ERROR_INVALID_VALUE;
        }

        strlcpy(cfg->cc_dev_rep_pci_addr, rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE);
    }

    return DOCA_SUCCESS;
}

void new_consumer_callback(struct doca_comch_event_consumer *event, struct doca_comch_connection *comch_connection,
                           uint32_t id)
{
    struct cc_ctx *ctx = comch_utils_get_user_data(comch_connection);
    (void)event;
    ctx->remote_consumer_ids[ctx->remote_consumer_counter] = id;
    ctx->remote_consumer_counter++;
}

void expired_consumer_callback(struct doca_comch_event_consumer *event, struct doca_comch_connection *comch_connection,
                               uint32_t id)
{
    /* Unused */

    (void)event;
    (void)comch_connection;
    (void)id;
}

void comch_recv_event_cb(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer, uint32_t msg_len,
                         struct doca_comch_connection *comch_connection)
{
    struct cc_ctx *cfg = comch_utils_get_user_data(comch_connection);
    struct metadata_msg *meta;

    (void)event;

    /* Only messages received should be of type metadata_msg */
    if (msg_len != sizeof(struct metadata_msg)) {
        DOCA_LOG_ERR("Invalid message length detected: %u", msg_len);
        cfg->svr_clt_sync = -1; // MOVE TO ERROR STATE - PERHAPS POPULATE A BAD VALUE IN MESSAGE FIELD
        return;
    }

    meta = (struct metadata_msg *)recv_buffer;

    /* If a start message is received, set client_thx_run to 1 */
    if (meta->type == START_MSG) {
        cfg->svr_clt_sync = 1;
        return;
    }

    /* If an end message is received, set client_thx_run back to 0 */
    if (meta->type == END_MSG) {
        cfg->svr_clt_sync = 0;
        return;
    }
}

/*
 * Helper function to tear down local memory allocated with prepare_local_memory()
 *
 * @local_mem [out]: local memory data to destroy
 */
static void destroy_local_memory(struct local_memory_bufs *local_mem)
{
    (void)doca_dev_close(local_mem->dev);
    free(local_mem->buf_data);
    (void)doca_mmap_destroy(local_mem->mmap);
    (void)doca_buf_inventory_destroy(local_mem->inv);
}

/*
 * Helper function to prepare local memory for use with doca_bufs and producer/consumer
 *
 * @local_mem [in]: struct of local memory data to be populated
 * @pci_addr [in]: address of device to associate memory with
 * @buf_len [in]: length of each buffer
 * @num_bufs [in]: total number of buffers required
 * @permissions [in]: bitwise combination of access flags - see enum doca_access_flag
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t prepare_local_memory(struct local_memory_bufs *local_mem, const char *pci_addr, size_t buf_len,
                                         uint32_t num_bufs, uint32_t permissions)
{
    size_t data_length = buf_len * num_bufs;
    size_t modulo;
    doca_error_t result;

    /* Open device to use for local memory registration */
    result = open_doca_device_with_pci(pci_addr, NULL, &local_mem->dev);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open device %s: %s", pci_addr, doca_error_get_descr(result));
        return result;
    }

    /* Aligned_alloc requires the length to be a multiple of the alignment value so may need to pad up */
    modulo = data_length % CACHE_ALIGN;
    local_mem->buf_data = (char *)aligned_alloc(CACHE_ALIGN, data_length + (modulo == 0 ? 0 : CACHE_ALIGN - modulo));
    if (local_mem->buf_data == NULL)
    {
        DOCA_LOG_ERR("Failed allocate buffer memory of length: %lu", data_length);
        result = DOCA_ERROR_NO_MEMORY;
        goto close_dev;
    }

    result = doca_mmap_create(&local_mem->mmap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create mmap: %s", doca_error_get_descr(result));
        goto free_data;
    }

    result = doca_mmap_set_permissions(local_mem->mmap, permissions);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set permissions on mmap: %s", doca_error_get_descr(result));
        goto destroy_mmap;
    }

    result = doca_mmap_add_dev(local_mem->mmap, local_mem->dev);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to add device to mmap: %s", doca_error_get_descr(result));
        goto destroy_mmap;
    }

    result = doca_mmap_set_memrange(local_mem->mmap, local_mem->buf_data, data_length);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set memrange of mmap: %s", doca_error_get_descr(result));
        goto destroy_mmap;
    }

    result = doca_mmap_start(local_mem->mmap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
        goto destroy_mmap;
    }

    result = doca_buf_inventory_create(num_bufs, &local_mem->inv);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create buffer inventory: %s", doca_error_get_descr(result));
        goto destroy_mmap;
    }

    result = doca_buf_inventory_start(local_mem->inv);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to start buffer inventory: %s", doca_error_get_descr(result));
        goto destroy_inv;
    }

    return DOCA_SUCCESS;

destroy_inv:
    (void)doca_buf_inventory_destroy(local_mem->inv);
destroy_mmap:
    (void)doca_mmap_destroy(local_mem->mmap);
free_data:
    free(local_mem->buf_data);
close_dev:
    (void)doca_dev_close(local_mem->dev);

    return result;
}

/* Client's callback for successful send_task completion */
static void client_send_task_completed_callback(struct doca_comch_producer_task_send *task, union doca_data task_user_data,
                                         union doca_data ctx_user_data)
{
    clt_thread_info_t *clt_thread_info = (clt_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    if (clt_thread_info->producer_state != FASTPATH_IN_PROGRESS)
        return;

    (clt_thread_info->clt_thread_data.producer_completed_msgs)++;
    // DOCA_LOG_INFO("Client sends %d messages out", clt_thread_info->producer_completed_msgs);

    /* Move to a stopping state once enough messages have been confirmed as sent */
    if (clt_thread_info->clt_thread_data.producer_completed_msgs == clt_thread_info->ctx->total_msgs)
    {
        clt_thread_info->producer_state = FASTPATH_COMPLETE;
        DOCA_LOG_INFO("Client thread completes all send tasks!");
        return;
    }

    doca_task_free(doca_comch_producer_task_send_as_task(task));
}

/* Client's callback for error on send_task completion */
static void client_send_task_fail_callback(struct doca_comch_producer_task_send *task, union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    clt_thread_info_t *clt_thread_info = (clt_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    /* Task fail errors may occur if context is in stopping state - this is expect */
    if (clt_thread_info->producer_state == FASTPATH_COMPLETE)
        return;

    DOCA_LOG_ERR("Received a producer send task completion error");
    clt_thread_info->producer_state = FASTPATH_ERROR;

    doca_task_free(doca_comch_producer_task_send_as_task(task));
}

/* Server's callback for successful send_task completion */
static void server_send_task_completed_callback(struct doca_comch_producer_task_send *task, union doca_data task_user_data,
                                         union doca_data ctx_user_data)
{
    svr_thread_info_t *svr_thread_info = (svr_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    if (svr_thread_info->producer_state != FASTPATH_IN_PROGRESS)
        return;

    doca_task_free(doca_comch_producer_task_send_as_task(task));
}

/* Callback for error on send_task completion */
static void server_send_task_fail_callback(struct doca_comch_producer_task_send *task, union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    svr_thread_info_t *svr_thread_info = (svr_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    /* Task fail errors may occur if context is in stopping state - this is expect */
    if (svr_thread_info->producer_state == FASTPATH_COMPLETE)
        return;

    DOCA_LOG_ERR("Received a producer send task completion error");
    svr_thread_info->producer_state = FASTPATH_ERROR;

    doca_task_free(doca_comch_producer_task_send_as_task(task));
}

/* Callback for successful post_recv completion */
static void client_recv_task_completed_callback(struct doca_comch_consumer_task_post_recv *recv_task,
                                         union doca_data task_user_data, union doca_data ctx_user_data)
{
    clt_thread_info_t *client_thread_info = (clt_thread_info_t *)ctx_user_data.ptr;

    struct doca_buf *recv_buf;
    doca_error_t result;
    (void)task_user_data;
    struct doca_comch_producer_task_send *send_task;

    (client_thread_info->clt_thread_data.consumer_completed_msgs)++;
    // DOCA_LOG_INFO("comsumer completed msg [%d]", client_thread_info->consumer_completed_msgs);

    if (client_thread_info->clt_thread_data.consumer_completed_msgs == client_thread_info->ctx->total_msgs)
    {
        client_thread_info->consumer_state = FASTPATH_COMPLETE;

        if (clock_gettime(CLOCK_TYPE_ID, &client_thread_info->clt_thread_data.end_time) != 0)
            DOCA_LOG_ERR("Failed to get timestamp");

        DOCA_LOG_INFO("Client[%d]'s consumer completed", client_thread_info->thread_id);

        return;
    }

    /* Client thread uses producer to send a new message */
    result = doca_comch_producer_task_send_alloc_init(client_thread_info->producer, client_thread_info->send_doca_buf, NULL, 0,
                                                      client_thread_info->peer_consumer_id, &send_task);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate a producer task: %s", doca_error_get_descr(result));
    }

    result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    while (result == DOCA_ERROR_AGAIN)
    {
        DOCA_LOG_INFO("KEEP SUBMITTING");
        result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    }
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to send task: %s", doca_error_get_descr(result));
        client_thread_info->producer_state = FASTPATH_ERROR;
    }
    // DOCA_LOG_INFO("submitted [%d] send req", client_thread_info->producer_submitted_msgs);
    client_thread_info->clt_thread_data.producer_submitted_msgs++;

    recv_buf = doca_comch_consumer_task_post_recv_get_buf(recv_task);

    void *recv_consumer_id;
    result = doca_buf_get_data(recv_buf, &recv_consumer_id);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to get data from recv_buf: %s", doca_error_get_descr(result));
        client_thread_info->consumer_state = FASTPATH_ERROR;
        return;
    }
    DOCA_LOG_INFO("Received Consumer ID [%u] \t Self Consumer ID [%u]", *(unsigned *)recv_consumer_id, (unsigned)client_thread_info->self_consumer_id);

    result = doca_buf_reset_data_len(recv_buf); /* Reset the buffer length so that it can be fully repopulated */
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to reset doca_buf length: %s", doca_error_get_descr(result));
        client_thread_info->consumer_state = FASTPATH_ERROR;
        return;
    }

    /* Client thread posts recv task (resubmit the same recv task) to the consumer */
    result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_task));
    while (result == DOCA_ERROR_AGAIN)
    {
        result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_task));
    }
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to resubmit post_recv task: %s", doca_error_get_descr(result));
        client_thread_info->consumer_state = FASTPATH_ERROR;
    }
    // DOCA_LOG_INFO("submitted [%d] recv req", client_thread_info->consumer_submitted_msgs);
    client_thread_info->clt_thread_data.consumer_submitted_msgs++;

    return;
}

/* Server's callback for successful post_recv completion */
static void server_recv_task_completed_callback(struct doca_comch_consumer_task_post_recv *recv_task,
                                         union doca_data task_user_data, union doca_data ctx_user_data)
{
    svr_thread_info_t *svr_thread_info = (svr_thread_info_t *)ctx_user_data.ptr;
    struct doca_buf *recv_buf;
    doca_error_t result;
    (void)task_user_data;
    struct doca_comch_producer_task_send *send_task;

    recv_buf = doca_comch_consumer_task_post_recv_get_buf(recv_task);

    /* Retrieve reomte consumer ID from the received data */
    void *recv_consumer_id;
    result = doca_buf_get_data(recv_buf, &recv_consumer_id);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to get data from recv_buf: %s", doca_error_get_descr(result));
        svr_thread_info->consumer_state = FASTPATH_ERROR;
        return;
    }
    DOCA_LOG_INFO("Received Consumer ID [%u] \t Peer Consumer ID [%u] \t Self Consumer ID [%u]", *(unsigned *)recv_consumer_id, (unsigned)svr_thread_info->peer_consumer_id, (unsigned)svr_thread_info->self_consumer_id);

    if (*(uint32_t *)recv_consumer_id != svr_thread_info->peer_consumer_id)
    {
        svr_thread_info->peer_consumer_id = *(uint32_t *)recv_consumer_id;
    }

    /* Reset the buffer length so that it can be fully repopulated */
    result = doca_buf_reset_data_len(recv_buf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to reset recv_buf length: %s", doca_error_get_descr(result));
        svr_thread_info->consumer_state = FASTPATH_ERROR;
        return;
    }

    /* Resubmit post recv task */
    result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_task));
    while (result == DOCA_ERROR_AGAIN)
    {
        result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_task));
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to resubmit post_recv task: %s", doca_error_get_descr(result));
        svr_thread_info->consumer_state = FASTPATH_ERROR;
    }

    result = doca_buf_set_data(svr_thread_info->send_doca_buf, &svr_thread_info->peer_consumer_id, sizeof(uint32_t));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set data pointer and data length in send_doca_buf: %s", doca_error_get_descr(result));
        svr_thread_info->producer_state = FASTPATH_ERROR;
    }

    /* Allocate a send task and submit */
    result = doca_comch_producer_task_send_alloc_init(svr_thread_info->producer, svr_thread_info->send_doca_buf, NULL, 0,
                                                      svr_thread_info->peer_consumer_id, &send_task);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate a producer task: %s", doca_error_get_descr(result));
    }

    result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    while (result == DOCA_ERROR_AGAIN)
    {
        DOCA_LOG_INFO("KEEP SUBMITTING");
        result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to send task: %s", doca_error_get_descr(result));
        svr_thread_info->producer_state = FASTPATH_ERROR;
    }

    return;
}

/* Callback for error on post_recv completion */
static void server_recv_task_fail_callback(struct doca_comch_consumer_task_post_recv *task, union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    svr_thread_info_t *svr_thread_info = (svr_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    /* Task fail errors may occur if context is in stopping state - this is expect */
    if (svr_thread_info->consumer_state == FASTPATH_COMPLETE)
        return;

    DOCA_LOG_ERR("Received a consumer post recv completion error");
    svr_thread_info->consumer_state = FASTPATH_ERROR;
}

static void client_recv_task_fail_callback(struct doca_comch_consumer_task_post_recv *task, union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    clt_thread_info_t *clt_thread_info = (clt_thread_info_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    /* Task fail errors may occur if context is in stopping state - this is expect */
    if (clt_thread_info->consumer_state == FASTPATH_COMPLETE)
        return;

    DOCA_LOG_ERR("Received a consumer post recv completion error");
    clt_thread_info->consumer_state = FASTPATH_ERROR;
}

/* Start a client thread */
static void *run_client(void *args)
{
    // Client thread context
    clt_thread_info_t *clt_thread_info = (clt_thread_info_t *)args;
    struct cc_ctx *ctx = clt_thread_info->ctx;
    union doca_data ctx_user_data = {0};

    struct doca_comch_consumer_task_post_recv *recv_task = NULL;
    struct doca_comch_producer_task_send *send_task = NULL;

    struct doca_buf *send_doca_buf = NULL; // Producer doca_buf
    struct doca_buf *recv_doca_buf = NULL; // Consumer doca_buf

    // Producer ring and Consumer ring
    struct doca_comch_producer *producer;
    struct doca_comch_consumer *consumer;

    // Task-2: do we need recv_local_mem and send_local_mem?
    struct local_memory_bufs local_mem;

    // Shared PE for Producer and Consumer
    struct doca_pe *client_pe;

    enum doca_ctx_states state;

    /* Total messages sent by the client's producer */
    uint32_t total_msgs = ctx->cfg->send_msg_nb;
    uint32_t total_tasks = 1; /* Client's concurrency is 1 */
    uint32_t msg_len = ctx->cfg->send_msg_size;
    uint32_t max_cap;

    uint32_t i;
    doca_error_t result, tmp_result;
    struct timespec ts = {
        .tv_nsec = SLEEP_IN_NANOS,
    };

    ctx->total_msgs = total_msgs;

    /* Consumer allocates a buffer of expected length for every task - must have write access */
    result = prepare_local_memory(&local_mem, ctx->cfg->cc_dev_pci_addr, msg_len, total_tasks * 2, DOCA_ACCESS_FLAG_PCI_READ_WRITE);
    if (result != DOCA_SUCCESS)
    {
        goto exit_thread;
    }

    /* Verify consumer can support message size */
    result = doca_comch_consumer_cap_get_max_buf_size(doca_dev_as_devinfo(local_mem.dev), &max_cap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to query consumer cap: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    if (max_cap < msg_len)
    {
        DOCA_LOG_ERR("Consumer does not support message size. Requested: %u, max: %u", msg_len, max_cap);
        result = DOCA_ERROR_INVALID_VALUE;
        goto destroy_local_mem;
    }

   /* Verify producer can support message size */
    result = doca_comch_producer_cap_get_max_buf_size(doca_dev_as_devinfo(local_mem.dev), &max_cap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to query producer cap: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    if (max_cap < msg_len)
    {
        DOCA_LOG_ERR("Producer does not support message size. Requested: %u, max: %u", msg_len, max_cap);
        result = DOCA_ERROR_INVALID_VALUE;
        goto destroy_local_mem;
    }

    /* Create a shared PE for Producer and Consumer */
    result = doca_pe_create(&client_pe);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create client progress engine: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    /* Create Producer Ring and Consumer Ring */
    result = doca_comch_consumer_create(ctx->comch_connection, local_mem.mmap, &consumer);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create consumer: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }
    clt_thread_info->consumer = consumer;

    result = doca_comch_producer_create(ctx->comch_connection, &producer);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create producer: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }
    clt_thread_info->producer = producer;

    /* Connect Producer Ring and Consumer Ring to PEs */
    result = doca_pe_connect_ctx(client_pe, doca_comch_consumer_as_ctx(consumer));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to connect consumer to pe: %s", doca_error_get_descr(result));
        goto destroy_consumer;
    }

    result = doca_pe_connect_ctx(client_pe, doca_comch_producer_as_ctx(producer));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to connect producer to pe: %s", doca_error_get_descr(result));
        goto destroy_producer;
    }

    /* Configure Producer send tasks and Consumer recv tasks */
    result = doca_comch_producer_task_send_set_conf(producer, client_send_task_completed_callback,
                                                    client_send_task_fail_callback, total_tasks);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to configure producer send tasks: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    result = doca_comch_consumer_task_post_recv_set_conf(consumer, client_recv_task_completed_callback,
                                                         client_recv_task_fail_callback, total_tasks);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to configure consumer recv tasks: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    /* Add client thread context data to callbacks */
    ctx_user_data.ptr = clt_thread_info;
    result = doca_ctx_set_user_data(doca_comch_consumer_as_ctx(consumer), ctx_user_data);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set consumer user data: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    result = doca_ctx_set_user_data(doca_comch_producer_as_ctx(producer), ctx_user_data);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set producer user data: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    /* Start DOCA Consumer context */
    result = doca_ctx_start(doca_comch_consumer_as_ctx(consumer));
    if (result != DOCA_ERROR_IN_PROGRESS)
    {
        DOCA_LOG_ERR("Failed to start consumer: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    /* Wait for consumer start to complete */
    (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(consumer), &state);
    while (state != DOCA_CTX_STATE_RUNNING)
    {
        (void)doca_pe_progress(client_pe);
        nanosleep(&ts, &ts);
        (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(consumer), &state);
    }
    clt_thread_info->consumer_state = FASTPATH_IN_PROGRESS;

    /* Assign a buffer and submit a post_recv message for every available task */
    result = doca_buf_inventory_buf_get_by_addr(local_mem.inv, local_mem.mmap, local_mem.buf_data, msg_len, &recv_doca_buf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate a consumer buf: %s", doca_error_get_descr(result));
        goto free_task_and_bufs;
    }

    /* Start DOCA Producer context */
    result = doca_ctx_start(doca_comch_producer_as_ctx(producer));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to start producer: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    /* Producer allocates a single buffer from registered local memory */
    result = doca_buf_inventory_buf_get_by_data(local_mem.inv, local_mem.mmap, local_mem.buf_data, msg_len, &send_doca_buf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to configure producer send tasks: %s", doca_error_get_descr(result));
        goto stop_producer;
    }
    clt_thread_info->send_doca_buf = send_doca_buf;

    /*
     * Wait on remote consumer to come up.
     * This is handled in the comch progress_engine.
     */
    while (ctx->remote_consumer_ids[clt_thread_info->thread_id] == 0)
    {
        nanosleep(&ts, &ts);
    }
    clt_thread_info->producer_state = FASTPATH_IN_PROGRESS;
    clt_thread_info->peer_consumer_id = ctx->remote_consumer_ids[clt_thread_info->thread_id];
    
    result = doca_comch_consumer_get_id(consumer, &clt_thread_info->self_consumer_id);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to get consumer ID: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }
    DOCA_LOG_INFO("Client thread's self consumer ID [%u]", (unsigned)clt_thread_info->self_consumer_id);
    
    result = doca_buf_set_data(send_doca_buf, &clt_thread_info->self_consumer_id, sizeof(uint32_t));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set data pointer and data length in send_doca_buf: %s", doca_error_get_descr(result));
        goto destroy_pe;
    }

    result = doca_comch_consumer_task_post_recv_alloc_init(consumer, recv_doca_buf, &recv_task);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate a post recv task: %s", doca_error_get_descr(result));
        goto free_task_and_bufs;
    }

    // Client's consumer submits a recv task
    result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_task));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to submit consumer post recv task: %s", doca_error_get_descr(result));
        goto free_task_and_bufs;
    }
    // DOCA_LOG_INFO("submitted [%d] recv req", ctx->ctx_data.consumer_submitted_msgs);
    clt_thread_info->clt_thread_data.consumer_submitted_msgs++;

    /* May need to wait for a post_recv message before being able to send */
    // Clients submit the first task; Server just creates the task but does not submit it.
    result = doca_comch_producer_task_send_alloc_init(producer, send_doca_buf, NULL, 0, clt_thread_info->peer_consumer_id, &send_task);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate a producer task: %s", doca_error_get_descr(result));
        goto free_task_and_bufs;
    }
    result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    while (result == DOCA_ERROR_AGAIN)
    {
        result = doca_task_submit(doca_comch_producer_task_send_as_task(send_task));
    }
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to submit producer send task: %s", doca_error_get_descr(result));
        goto free_task_and_bufs;
    }
    // DOCA_LOG_INFO("submitted [%d] send req", ctx->ctx_data.producer_submitted_msgs);
    clt_thread_info->clt_thread_data.producer_submitted_msgs++;


    /* Progress until all expected messages have been received or an error occurred */
    DOCA_LOG_INFO("Enter Client Event Loop.");
    while (1)
    {
        if (clt_thread_info->producer_state == FASTPATH_IN_PROGRESS || clt_thread_info->consumer_state == FASTPATH_IN_PROGRESS)
        {
            doca_pe_progress(client_pe);    
        }
        else
        {
            DOCA_LOG_INFO("Leaving client event loop.");
            break;
        }
    }

    if (clt_thread_info->consumer_state == FASTPATH_ERROR)
    {
        result = DOCA_ERROR_BAD_STATE;
        DOCA_LOG_ERR("Consumer datapath failed");
    }

free_task_and_bufs:
    /* Free all allocated buffers and tasks */
    for (i = 0; i < total_tasks; i++)
    {
        if (recv_doca_buf != NULL)
            doca_buf_dec_refcount(recv_doca_buf, NULL);
        if (recv_task != NULL)
            doca_task_free(doca_comch_consumer_task_post_recv_as_task(recv_task));
        if (send_doca_buf != NULL)
            doca_buf_dec_refcount(send_doca_buf, NULL);
        if (send_task != NULL)
            doca_task_free(doca_comch_producer_task_send_as_task(send_task));
    }

// stop_consumer:
    tmp_result = doca_ctx_stop(doca_comch_consumer_as_ctx(consumer));
    if (tmp_result != DOCA_ERROR_IN_PROGRESS && tmp_result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to stop consumer: %s", doca_error_get_descr(tmp_result));
        goto destroy_consumer;
    }

    /* Wait for consumer stop to complete */
    (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(consumer), &state);
    while (state != DOCA_CTX_STATE_IDLE)
    {
        (void)doca_pe_progress(client_pe);
        nanosleep(&ts, &ts);
        (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(consumer), &state);
    }

stop_producer:
    tmp_result = doca_ctx_stop(doca_comch_producer_as_ctx(producer));
    if (tmp_result != DOCA_ERROR_IN_PROGRESS && tmp_result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to stop producer: %s", doca_error_get_descr(tmp_result));
        goto destroy_producer;
    }

    /* Wait for producer stop to complete */
    (void)doca_ctx_get_state(doca_comch_producer_as_ctx(producer), &state);
    while (state != DOCA_CTX_STATE_IDLE)
    {
        (void)doca_pe_progress(client_pe);
        nanosleep(&ts, &ts);
        (void)doca_ctx_get_state(doca_comch_producer_as_ctx(producer), &state);
    }

destroy_consumer:
    tmp_result = doca_comch_consumer_destroy(consumer);
    if (tmp_result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy consumer: %s", doca_error_get_descr(tmp_result));

destroy_producer:
    tmp_result = doca_comch_producer_destroy(producer);
    if (tmp_result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy producer: %s", doca_error_get_descr(tmp_result));

destroy_pe:
    tmp_result = doca_pe_destroy(client_pe);
    if (tmp_result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy client PE: %s", doca_error_get_descr(tmp_result));

destroy_local_mem:
    destroy_local_memory(&local_mem);

exit_thread:
    atomic_fetch_sub(&ctx->active_threads, 1);

    return NULL;
}

/* Start a server thread */
static void *run_server(void *args)
{
    uint32_t i;
 
    // User-defined context
    struct cc_ctx *ctx = (struct cc_ctx *)args;
    svr_thread_info_t svr_thread_info[num_client_threads];
    for (i = 0; i < num_client_threads; i++)
    {
        svr_thread_info[i].ctx = ctx;
    }
    union doca_data ctx_user_data = {0};

    struct doca_comch_consumer_task_post_recv *recv_tasks[num_client_threads];
    struct doca_comch_producer_task_send *send_tasks[num_client_threads];

    struct doca_buf *send_doca_bufs[num_client_threads]; // Producer doca_bufs
    struct doca_buf *recv_doca_bufs[num_client_threads]; // Consumer doca_bufs

    // Producer rings and Consumer rings in Server
    // struct doca_comch_producer *producers[num_client_threads];
    // struct doca_comch_consumer *consumers[num_client_threads];

    // Task-2: do we need recv_local_mem and send_local_mem?
    struct local_memory_bufs local_mem;

    // Shared PE for Producer and Consumer
    struct doca_pe *server_pe;

    enum doca_ctx_states state;

    uint32_t total_tasks = num_client_threads;
    uint32_t msg_len = ctx->cfg->send_msg_size;
    uint32_t max_cap;
    doca_error_t result, tmp_result;

    struct timespec ts = {
        .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Consumer allocates a buffer of expected length for every task - must have write access */
    result = prepare_local_memory(&local_mem, ctx->cfg->cc_dev_pci_addr, msg_len, total_tasks * 2, DOCA_ACCESS_FLAG_PCI_READ_WRITE);
    if (result != DOCA_SUCCESS)
    {
        goto exit_thread;
    }

    /* Verify consumer can support message size */
    result = doca_comch_consumer_cap_get_max_buf_size(doca_dev_as_devinfo(local_mem.dev), &max_cap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to query consumer cap: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    if (max_cap < msg_len)
    {
        DOCA_LOG_ERR("Consumer does not support message size. Requested: %u, max: %u", msg_len, max_cap);
        result = DOCA_ERROR_INVALID_VALUE;
        goto destroy_local_mem;
    }

   /* Verify producer can support message size */
    result = doca_comch_producer_cap_get_max_buf_size(doca_dev_as_devinfo(local_mem.dev), &max_cap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to query producer cap: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    if (max_cap < msg_len)
    {
        DOCA_LOG_ERR("Producer does not support message size. Requested: %u, max: %u", msg_len, max_cap);
        result = DOCA_ERROR_INVALID_VALUE;
        goto destroy_local_mem;
    }

    /* Create a shared PE for Producer and Consumer */
    result = doca_pe_create(&server_pe);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create server progress engine: %s", doca_error_get_descr(result));
        goto destroy_local_mem;
    }

    /* Create Consumer Rings */
    for (i = 0; i < num_client_threads; i++)
    {
        result = doca_comch_consumer_create(ctx->comch_connection, local_mem.mmap, &svr_thread_info[i].consumer);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to create consumer: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Connect Consumer Rings to PEs */
        result = doca_pe_connect_ctx(server_pe, doca_comch_consumer_as_ctx(svr_thread_info[i].consumer));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to connect consumer to pe: %s", doca_error_get_descr(result));
            goto destroy_consumer;
        }

        /* Configure Consumer recv tasks */
        result = doca_comch_consumer_task_post_recv_set_conf(svr_thread_info[i].consumer, server_recv_task_completed_callback,
                                                            server_recv_task_fail_callback, 1);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to configure consumer recv tasks: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Add user data to update context from callbacks */
        ctx_user_data.ptr = &svr_thread_info[i];
        result = doca_ctx_set_user_data(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer), ctx_user_data);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to set consumer user data: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Start DOCA consumer context */
        result = doca_ctx_start(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer));
        if (result != DOCA_ERROR_IN_PROGRESS)
        {
            DOCA_LOG_ERR("Failed to start consumer: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Wait for consumer start to complete */
        (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer), &state);
        while (state != DOCA_CTX_STATE_RUNNING)
        {
            (void)doca_pe_progress(server_pe);
            nanosleep(&ts, &ts);
            (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer), &state);
        }
        svr_thread_info[i].consumer_state = FASTPATH_IN_PROGRESS;

        /* Consumer assigns a buffer and submit a post_recv message for every available task */
        result = doca_buf_inventory_buf_get_by_addr(local_mem.inv, local_mem.mmap, local_mem.buf_data, msg_len, &recv_doca_bufs[i]);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to allocate a consumer buf: %s", doca_error_get_descr(result));
            goto free_task_and_bufs;
        }

        result = doca_comch_consumer_get_id(svr_thread_info[i].consumer, &svr_thread_info[i].self_consumer_id);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to get consumer ID: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }
        DOCA_LOG_INFO("Server's [#%d] self consumer ID [%u]", (int)i, (unsigned)svr_thread_info[i].self_consumer_id);
    }

    /* Wait for client threads to start remote consumers */ 
    while (ctx->remote_consumer_counter < num_client_threads)
    {
        nanosleep(&ts, &ts);
    }
    DOCA_LOG_INFO("All remote consumers have been connected");

    /* Create Producer Rings */
    for (i = 0; i < num_client_threads; i++)
    {
        result = doca_comch_producer_create(ctx->comch_connection, &svr_thread_info[i].producer);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to create producer: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Connect Producer Ring to PEs */
        result = doca_pe_connect_ctx(server_pe, doca_comch_producer_as_ctx(svr_thread_info[i].producer));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to connect producer to pe: %s", doca_error_get_descr(result));
            goto destroy_producer;
        }

        /* Configure Producer send tasks */
        result = doca_comch_producer_task_send_set_conf(svr_thread_info[i].producer, server_send_task_completed_callback,
                                                        server_send_task_fail_callback, 1);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to configure producer send tasks: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Add user data to update context from callbacks */
        ctx_user_data.ptr = &svr_thread_info[i];
        result = doca_ctx_set_user_data(doca_comch_producer_as_ctx(svr_thread_info[i].producer), ctx_user_data);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to set producer user data: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Start DOCA producer context */
        result = doca_ctx_start(doca_comch_producer_as_ctx(svr_thread_info[i].producer));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to start producer: %s", doca_error_get_descr(result));
            goto destroy_pe;
        }

        /* Producer allocates a single buffer from registered local memory */
        result = doca_buf_inventory_buf_get_by_data(local_mem.inv, local_mem.mmap, local_mem.buf_data, msg_len, &send_doca_bufs[i]);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to configure producer send tasks: %s", doca_error_get_descr(result));
            goto stop_producer;
        }
        svr_thread_info[i].send_doca_buf = send_doca_bufs[i];
        svr_thread_info[i].producer_state = FASTPATH_IN_PROGRESS;

        svr_thread_info[i].peer_consumer_id = ctx->remote_consumer_ids[i];
    }

    /* Allocate recv tasks and submit */
    for (i = 0; i < num_client_threads; i++)
    {
        result = doca_comch_consumer_task_post_recv_alloc_init(svr_thread_info[i].consumer, recv_doca_bufs[i], &recv_tasks[i]);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to allocate a post recv task: %s", doca_error_get_descr(result));
            goto free_task_and_bufs;
        }

        result = doca_task_submit(doca_comch_consumer_task_post_recv_as_task(recv_tasks[i]));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to submit consumer post recv task: %s", doca_error_get_descr(result));
            goto free_task_and_bufs;
        }
        // DOCA_LOG_INFO("submitted [%d] recv req", ctx->ctx_data.consumer_submitted_msgs);
    }

    /* Progress until all expected messages have been received or an error occurred */
    DOCA_LOG_INFO("Enter Server Event Loop.");
    while (1)
    {
        // TODO: graceful termination
        doca_pe_progress(server_pe);    
    }

free_task_and_bufs:
    /* Free all allocated buffers and tasks */
    for (i = 0; i < num_client_threads; i++)
    {
        if (send_doca_bufs[i] != NULL)
            doca_buf_dec_refcount(send_doca_bufs[i], NULL);
        if (recv_doca_bufs[i] != NULL)
            doca_buf_dec_refcount(recv_doca_bufs[i], NULL);
        if (recv_tasks[i] != NULL)
            doca_task_free(doca_comch_consumer_task_post_recv_as_task(recv_tasks[i]));
        if (send_tasks[i] != NULL)
            doca_task_free(doca_comch_producer_task_send_as_task(send_tasks[i]));
    }

// stop_consumer:
    for (i = 0; i < num_client_threads; i++)
    {
        tmp_result = doca_ctx_stop(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer));
        if (tmp_result != DOCA_ERROR_IN_PROGRESS && tmp_result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to stop consumer: %s", doca_error_get_descr(tmp_result));
            goto destroy_consumer;
        }

        /* Wait for consumer stop to complete */
        (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer), &state);
        while (state != DOCA_CTX_STATE_IDLE)
        {
            (void)doca_pe_progress(server_pe);
            nanosleep(&ts, &ts);
            (void)doca_ctx_get_state(doca_comch_consumer_as_ctx(svr_thread_info[i].consumer), &state);
        }
    }

stop_producer:
    for (i = 0; i < num_client_threads; i++)
    {
        tmp_result = doca_ctx_stop(doca_comch_producer_as_ctx(svr_thread_info[i].producer));
        if (tmp_result != DOCA_ERROR_IN_PROGRESS && tmp_result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to stop producer: %s", doca_error_get_descr(tmp_result));
            goto destroy_producer;
        }

        /* Wait for producer stop to complete */
        (void)doca_ctx_get_state(doca_comch_producer_as_ctx(svr_thread_info[i].producer), &state);
        while (state != DOCA_CTX_STATE_IDLE)
        {
            (void)doca_pe_progress(server_pe);
            nanosleep(&ts, &ts);
            (void)doca_ctx_get_state(doca_comch_producer_as_ctx(svr_thread_info[i].producer), &state);
        }
    }

destroy_consumer:
    for (i = 0; i < num_client_threads; i++)
    {
        tmp_result = doca_comch_consumer_destroy(svr_thread_info[i].consumer);
        if (tmp_result != DOCA_SUCCESS)
            DOCA_LOG_ERR("Failed to destroy consumer: %s", doca_error_get_descr(tmp_result));
    }

destroy_producer:
    for (i = 0; i < num_client_threads; i++)
    {
        tmp_result = doca_comch_producer_destroy(svr_thread_info[i].producer);
        if (tmp_result != DOCA_SUCCESS)
            DOCA_LOG_ERR("Failed to destroy producer: %s", doca_error_get_descr(tmp_result));
    }

destroy_pe:
    tmp_result = doca_pe_destroy(server_pe);
    if (tmp_result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy consumer pe: %s", doca_error_get_descr(tmp_result));

destroy_local_mem:
    destroy_local_memory(&local_mem);

exit_thread:
    atomic_fetch_sub(&ctx->active_threads, 1);

    return NULL;
}

/*
 * Start client threads and wait for them to finish
 *
 * @ctx [in]: Thread context
 * @comch_cfg [in]: Comch channel to progress on
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t start_clt_threads(struct cc_ctx *ctx, struct comch_cfg *comch_cfg)
{
    doca_error_t result;
    int running_client_threads;
    uint32_t i;

    clt_thread_info_t clt_thread_info[num_client_threads];

    /* set count to determine when threads have finished */
    atomic_init(&ctx->active_threads, num_client_threads);
    running_client_threads = num_client_threads;

    for (i = 0; i < num_client_threads; i++)
    {
        clt_thread_info[i].thread_id = i;
        clt_thread_info[i].ctx = ctx;
        if (pthread_create(&(clt_thread_info[i].clt_t), NULL, run_client, (void *) &clt_thread_info[i]) != 0)
        {
            DOCA_LOG_ERR("Failed to start client thread");
            return DOCA_ERROR_BAD_STATE;
        }
    }

    for (i = 0; i < num_client_threads; i++)
    {
        if (pthread_detach(clt_thread_info[i].clt_t) != 0)
        {
            DOCA_LOG_ERR("Failed to detach client thread");
            return DOCA_ERROR_BAD_STATE;
        }
    }

    /*
     * Progress the comch PE while waiting for the threads to finish.
     * Comch handles producer and consumer control messages so must continue to run.
     */
    while (running_client_threads > 0)
    {
        result = comch_utils_progress_connection(comch_util_get_connection(comch_cfg));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Error in comch progression: %s", doca_error_get_descr(result));
            return result;
        }
        running_client_threads = atomic_load(&ctx->active_threads);
    }

    long long total_rtt = 0;
    long total_messages = 0;
    float total_request_rate = 0;

    /* Wait for client threads to complete and aggregate metrics */
    for (i = 0; i < num_client_threads; i++) {
        total_rtt += clt_thread_info[i].clt_thread_data.total_rtt;
        total_messages += clt_thread_info[i].clt_thread_data.total_messages;
        total_request_rate += clt_thread_info[i].clt_thread_data.request_rate;
    }

    printf("Average RTT: %lld us\n", total_rtt / total_messages);
    printf("Total Request Rate: %f messages/s\n", total_request_rate);

    return DOCA_SUCCESS;
}

/*
 * Start server thread and wait for it to finish
 *
 * @ctx [in]: Thread context
 * @comch_cfg [in]: Comch channel to progress on
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t start_svr_thread(struct cc_ctx *ctx, struct comch_cfg *comch_cfg)
{
    doca_error_t result;
    int running_svr_threads;
    pthread_t svr_t;

    /* set count to determine when threads have finished */
    atomic_init(&ctx->active_threads, 1);
    running_svr_threads = 1;

    if (pthread_create(&svr_t, NULL, run_server, (void *)ctx) != 0)
    {
        DOCA_LOG_ERR("Failed to start sendto thread");
        return DOCA_ERROR_BAD_STATE;
    }

    if (pthread_detach(svr_t) != 0)
    {
        DOCA_LOG_ERR("Failed to detach sendto thread");
        return DOCA_ERROR_BAD_STATE;
    }

    /*
     * Progress the comch PE while waiting for the threads to finish.
     * Comch handles producer and consumer control messages so must continue to run.
     */
    while (running_svr_threads > 0)
    {
        result = comch_utils_progress_connection(comch_util_get_connection(comch_cfg));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Error in comch progression: %s", doca_error_get_descr(result));
            return result;
        }
        running_svr_threads = atomic_load(&ctx->active_threads);
    }

    return DOCA_SUCCESS;
}

doca_error_t comch_producer_consumer_start(struct comch_cfg *comch_cfg, struct sc_config *cfg, struct cc_ctx *ctx)
{
    doca_error_t result;

    // pthread_t client_threads[num_client_threads];
    // client_thread_data_t client_thread_data[num_client_threads];
    uint32_t remote_consumer_ids[num_client_threads];

    ctx->comch_connection = comch_util_get_connection(comch_cfg);
    ctx->cfg = cfg;
    ctx->svr_clt_sync = 0; // Server and client haven't sync'ed yet
    ctx->remote_consumer_ids = remote_consumer_ids;
    ctx->remote_consumer_counter = 0;

    /* Send a comch metadata message to the other side to sync' */
    struct metadata_msg meta = {0};
    meta.type = START_MSG;
    result = comch_utils_send(comch_util_get_connection(comch_cfg), &meta, sizeof(struct metadata_msg));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to send metadata message: %s", doca_error_get_descr(result));
        return result;
    }

    /* Wait until the metadata message from the opposite side has been received */
    while (ctx->svr_clt_sync == 0)
    {
        result = comch_utils_progress_connection(comch_util_get_connection(comch_cfg));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to progress comch: %s", doca_error_get_descr(result));
            return result;
        }
    }

    if (ctx->svr_clt_sync < 0)
    {
        DOCA_LOG_ERR("Got a bad metadata message on comch");
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (cfg->mode == SC_MODE_DPU)
    {
        /* Starting a single server thread on DPU */
        ctx->ctx_data.mode = cfg->mode;

        result = start_svr_thread(ctx, comch_cfg);
        if (result != DOCA_SUCCESS)
        {
            return result;
        }
    }
    else
    {
        /* Starting multiple client threads on Host */
        ctx->n_clts = num_client_threads;
        ctx->ctx_data.mode = cfg->mode;

        result = start_clt_threads(ctx, comch_cfg);
        if (result != DOCA_SUCCESS)
        {
            return result;
        }
    }

    /*
     * To ensure that both sides have finished with the comch channel send an end message from DPU to host.
     * On the host side, wait to receive said message (sets expected msgs back to 0).
     * Comch utils enforces that the client must disconnect from the server before it can be destroyed.
     */
    if (cfg->mode == SC_MODE_DPU)
    {
        meta.type = END_MSG;
        result = comch_utils_send(comch_util_get_connection(comch_cfg), &meta, sizeof(struct metadata_msg));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to send metadata message: %s", doca_error_get_descr(result));
            return result;
        }
    }
    else
    {
        while (ctx->svr_clt_sync != 0)
        {
            result = comch_utils_progress_connection(comch_util_get_connection(comch_cfg));
            if (result != DOCA_SUCCESS)
            {
                DOCA_LOG_ERR("Failed to progress comch: %s", doca_error_get_descr(result));
                return result;
            }
        }
    }

    DOCA_LOG_INFO("comch_producer_consumer_start done");

    return result;
}

doca_error_t register_secure_channel_params(void)
{
    doca_error_t result;

    struct doca_argp_param *message_size_param, *messages_number_param, *pci_addr_param, *rep_pci_addr_param;

    /* Create and register message to send param */
    result = doca_argp_param_create(&message_size_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
        return result;
    }
    doca_argp_param_set_short_name(message_size_param, "s");
    doca_argp_param_set_long_name(message_size_param, "msg-size");
    doca_argp_param_set_description(message_size_param, "Message size to be sent");
    doca_argp_param_set_callback(message_size_param, message_size_callback);
    doca_argp_param_set_type(message_size_param, DOCA_ARGP_TYPE_INT);
    doca_argp_param_set_mandatory(message_size_param);
    result = doca_argp_register_param(message_size_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create and register number of message param */
    result = doca_argp_param_create(&messages_number_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
        return result;
    }
    doca_argp_param_set_short_name(messages_number_param, "n");
    doca_argp_param_set_long_name(messages_number_param, "num-msgs");
    doca_argp_param_set_description(messages_number_param, "Number of messages to be sent");
    doca_argp_param_set_callback(messages_number_param, messages_number_callback);
    doca_argp_param_set_type(messages_number_param, DOCA_ARGP_TYPE_INT);
    doca_argp_param_set_mandatory(messages_number_param);
    result = doca_argp_register_param(messages_number_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create and register Comm Channel DOCA device PCI address */
    result = doca_argp_param_create(&pci_addr_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
        return result;
    }
    doca_argp_param_set_short_name(pci_addr_param, "p");
    doca_argp_param_set_long_name(pci_addr_param, "pci-addr");
    doca_argp_param_set_description(pci_addr_param, "DOCA Comch device PCI address");
    doca_argp_param_set_callback(pci_addr_param, dev_pci_addr_callback);
    doca_argp_param_set_type(pci_addr_param, DOCA_ARGP_TYPE_STRING);
    doca_argp_param_set_mandatory(pci_addr_param);
    result = doca_argp_register_param(pci_addr_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create and register Comm Channel DOCA device representor PCI address */
    result = doca_argp_param_create(&rep_pci_addr_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
        return result;
    }
    doca_argp_param_set_short_name(rep_pci_addr_param, "r");
    doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
    doca_argp_param_set_description(rep_pci_addr_param,
                                    "DOCA Comch device representor PCI address (needed only on DPU)");
    doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
    doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(rep_pci_addr_param);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
        return result;
    }

    /* Register version callback for DOCA SDK & RUNTIME */
    result = doca_argp_register_version_callback(sdk_version_callback);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register version callback: %s", doca_error_get_descr(result));
        return result;
    }

    return DOCA_SUCCESS;
}
