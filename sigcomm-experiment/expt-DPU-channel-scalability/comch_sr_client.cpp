#include <cstdlib>
#include <functional>
#include <iostream>
#include <thread>
#include <vector>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <iostream>
#include <mutex>
#include <vector>

#include "comch_ctrl_path_common.h"
#include "comch_utils.h"
#include "common_doca.h"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "sys/epoll.h"

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

const char *g_server_name = "comch_ctrl_path_sample_server";
const uint32_t n_thread = 512;
DOCA_LOG_REGISTER(COMCH_CLIENT::MAIN);

double g_latency = 0.0;
double g_rps = 0.0;
std::mutex g_mutex;

struct my_comch_ctx
{
    struct doca_dev *hw_dev;          /* Device used in the sample */
    struct doca_pe *pe;               /* PE object used in the sample */
    struct doca_comch_client *client; /* Client object used in the sample */
    struct doca_ctx *ctx;
    const char *text;                         /* Message to send to the server */
    uint32_t text_len;                        /* Length of message to send to the server */
    struct doca_comch_connection *connection; /* Connection object used in the sample */
    doca_error_t result;                      /* Holds result will be updated in callbacks */
    bool finish;                              /* Controls whether progress loop should be run */
    uint32_t n_msg;
    struct timespec start_time;
    struct timespec end_time;
    uint32_t expected_msg_n;
    int ep_fd;
};

static void client_comch_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    // the user data is the ctx userdata
    struct my_comch_ctx *data = (struct my_comch_ctx *)user_data.ptr;
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC client context has been stopped");
        /* We can stop progressing the PE */

        data->finish = true;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        // need to get the connection object first
        DOCA_LOG_INFO("client context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        struct doca_comch_connection *conn;
        doca_error_t result;
        if (clock_gettime(CLOCK_TYPE_ID, &data->start_time) != 0)
        {
            DOCA_LOG_ERR("Failed to get timestamp");
        }
        struct doca_comch_task_send *task;
        result = doca_comch_client_get_connection(data->client, &conn);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to get connection from client with error = %s", doca_error_get_name(result));
            (void)doca_ctx_stop(doca_comch_client_as_ctx(data->client));
        }
        data->connection = conn;

        result = doca_comch_connection_set_user_data(conn, user_data);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to set user_data for connection with error = %s", doca_error_get_name(result));
        }
        data->result =
            comch_client_send_msg(data->client, data->connection, data->text, data->text_len, user_data, &task);
        break;
        DOCA_LOG_INFO("CC client context is running");

        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        DOCA_LOG_INFO("client context entered into stopping state");
        break;
    default:
        break;
    }
}
static void client_message_recv_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer,
                                         uint32_t msg_len, struct doca_comch_connection *comch_connection)
{
    doca_error_t result;
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct my_comch_ctx *sample_objects = (struct my_comch_ctx *)user_data.ptr;
    struct doca_comch_task_send *task;

    /* This argument is not in use */
    (void)event;

    /* DOCA_LOG_INFO("Message received: '%.*s'", (int)msg_len, recv_buffer); */
    sample_objects->n_msg++;
    if (sample_objects->n_msg < sample_objects->expected_msg_n)
    {
        result =
            comch_client_send_msg(sample_objects->client, comch_connection, recv_buffer, msg_len, user_data, &task);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("failed to send pong");
        }
    }
    else
    {
        if (clock_gettime(CLOCK_TYPE_ID, &sample_objects->end_time) != 0)
        {
            DOCA_LOG_ERR("Failed to get timestamp");
        }
        sample_objects->result = DOCA_SUCCESS;
        (void)doca_ctx_stop(doca_comch_client_as_ctx(sample_objects->client));
    }
}
void run_clients(int id, void *cfg)
{
    struct comch_config *config = (struct comch_config *)cfg;
    struct my_comch_ctx ctx;
    memset(&ctx, 0, sizeof(struct my_comch_ctx));

    ctx.text = new char(config->send_msg_size);
    ctx.text_len = config->send_msg_size;
    ctx.expected_msg_n = config->send_msg_nb;
    ctx.finish = false;

    doca_error_t result;
    struct comch_ctrl_path_client_cb_config cb_cfg = {.send_task_comp_cb = basic_send_task_completion_callback,
                                                      .send_task_comp_err_cb = basic_send_task_completion_err_callback,
                                                      .msg_recv_cb = client_message_recv_callback,
                                                      .data_path_mode = false,
                                                      .new_consumer_cb = NULL,
                                                      .expired_consumer_cb = NULL,
                                                      .ctx_user_data = &ctx,
                                                      .ctx_state_changed_cb = client_comch_state_changed_callback};

    /* Open DOCA device according to the given PCI address */
    result = open_doca_device_with_pci(config->comch_dev_pci_addr, NULL, &(ctx.hw_dev));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
        return;
    }

    result =
        init_comch_ctrl_path_client_with_ctx(g_server_name, ctx.hw_dev, &cb_cfg, &(ctx.client), &(ctx.pe), &(ctx.ctx));
    DOCA_LOG_ERR("the addr of client %p", (void*)ctx.client);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init cc client with error = %s", doca_error_get_name(result));
        return;
    }

    int ep_fd;
    ep_fd = epoll_create1(0);
    if (ep_fd == -1)
    {
        DOCA_LOG_ERR("Failed to create epoll_fd");
    }
    result = register_pe_event(ctx.pe, ep_fd);

    struct epoll_event ep_event
    {
    };
    int ret = 0;
    DOCA_LOG_INFO("epoll event loop");
    while (ctx.finish != true)
    {
        doca_pe_request_notification(ctx.pe);
        ret = epoll_wait(ep_fd, &ep_event, 1, -1);
        if (ret == -1)
        {
            DOCA_LOG_ERR("failed to wait ep event");
        }
        doca_pe_clear_notification(ctx.pe, 0);
        while (doca_pe_progress(ctx.pe))
        {
        }
    }
    if (ctx.text != nullptr)
    {
        delete ctx.text;
    }

    double tt_time = calculate_timediff_usec(&ctx.end_time, &ctx.start_time);
    double rps = ctx.expected_msg_n / tt_time * USEC_PER_SEC;
    DOCA_LOG_INFO("thread %d is running", id);
    {
        std::lock_guard<std::mutex> lock(g_mutex); // Automatically unlocks when out of scope
        g_rps += rps;
        g_latency += tt_time;
    }
    DOCA_LOG_INFO("Thread %d speed: %f usec", id, tt_time/ config->send_msg_nb);
    DOCA_LOG_INFO("Thread %d rps: %f ", id, rps);
}

void client_function(uint32_t num_threads, std::function<void(int, void *)> func, struct comch_config *cfg)
{
    std::vector<std::thread> threads;

    // Create and run threads
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(func, i, (void *)cfg); // Pass thread index to function
    }

    // Join threads to wait for completion
    for (auto &t : threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
}
// void sc_start(uint32_t n_process);

int main(int argc, char **argv)
{
    struct comch_config cfg;
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;

    /* Set the default configuration values, client so no need for the comch_dev_rep_pci_addr field*/
    strcpy(cfg.comch_dev_pci_addr, DEFAULT_PCI_ADDR);
    strcpy(cfg.text, DEFAULT_MESSAGE);
    cfg.text_size = strlen(DEFAULT_MESSAGE);
    cfg.is_epoll = false;

    /* Register a logger backend */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    /* Register a logger backend for internal SDK errors and warnings */
    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS)
        goto sample_exit;
    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    DOCA_LOG_INFO("Starting the sample");

    /* Parse cmdline/json arguments */
    result = doca_argp_init("doca_comch_ctrl_path_client", &cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    result = register_comch_params();
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register CC client sample parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    client_function(cfg.n_thread, run_clients, &cfg);

    DOCA_LOG_INFO("the latency is %f", g_latency);
    DOCA_LOG_INFO("the rps is %f", g_rps);

    exit_status = EXIT_SUCCESS;

argp_cleanup:
    doca_argp_destroy();
sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}
