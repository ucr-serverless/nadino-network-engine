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

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

const char *g_server_name = "comch_ctrl_path_sample_server";

DOCA_LOG_REGISTER(COMCH_CLIENT::MAIN);

struct my_comch_ctx
{
    struct doca_dev *hw_dev;          /* Device used in the sample */
    struct doca_pe *pe;               /* PE object used in the sample */
    struct doca_dev_rep *rep_dev;     /* Device representor used in the sample */
    struct doca_comch_client *client; /* Client object used in the sample */
    struct doca_ctx *ctx;
    struct doca_comch_server *server;
    const char *text;                         /* Message to send to the server */
    uint32_t text_len;                        /* Length of message to send to the server */
    struct doca_comch_connection *connection; /* Connection object used in the sample */
    doca_error_t result;                      /* Holds result will be updated in callbacks */
    bool finish;                              /* Controls whether progress loop should be run */
    int n_msg;
    struct timespec start_time;
    struct timespec end_time;
    uint32_t expected_msg_n;
    int ep_fd;
    size_t n_client_connected;
    bool client_connected;
};
static void server_comch_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    struct my_comch_ctx *data = (struct my_comch_ctx *)user_data.ptr;
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC server context has been stopped");
        /* We can stop progressing the PE */

        data->finish = true;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        DOCA_LOG_ERR("server context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("CC server context is running. Waiting for clients to connect");

        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        DOCA_LOG_INFO("CC server context entered into stopping state. Terminating connections with clients");
        break;
    default:
        break;
    }
}
void server_connection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                      struct doca_comch_connection *comch_conn, uint8_t change_success)
{

    (void)event;
    (void)change_success;
    union doca_data data = doca_comch_connection_get_user_data(comch_conn);
    struct my_comch_ctx *user_data = (struct my_comch_ctx *)data.ptr;
    user_data->n_client_connected--;
    DOCA_LOG_INFO("client disconnected, %zu client remains", user_data->n_client_connected);
    if (user_data->n_client_connected == 0)
    {
        doca_ctx_stop(user_data->ctx);
        DOCA_LOG_INFO("closing ctx");
    }
}
void server_disconnection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                         struct doca_comch_connection *comch_conn, uint8_t change_success)
{

    /* This argument is not in use */
    (void)event;
    (void)change_success;
    DOCA_LOG_INFO("client connected");
    union doca_data data = doca_comch_connection_get_user_data(comch_conn);
    struct my_comch_ctx *user_data = (struct my_comch_ctx *)data.ptr;
    user_data->n_client_connected++;
    DOCA_LOG_INFO("client connected, %zu client now", user_data->n_client_connected);
}
doca_error_t run_server(void *cfg)
{
    struct comch_config *config = (struct comch_config *)cfg;
    struct my_comch_ctx ctx;
    memset(&ctx, 0, sizeof(struct my_comch_ctx));

    ctx.client_connected = false;
    ctx.n_client_connected = 0;

    doca_error_t result;
    struct comch_ctrl_path_server_cb_config cb_cfg = {.send_task_comp_cb = basic_send_task_completion_callback,
                                                      .send_task_comp_err_cb = basic_send_task_completion_err_callback,
                                                      .msg_recv_cb = NULL,
                                                      .server_connection_event_cb = server_connection_event_callback,
                                                      .server_disconnection_event_cb =
                                                          server_disconnection_event_callback,
                                                      .data_path_mode = false,
                                                      .new_consumer_cb = NULL,
                                                      .expired_consumer_cb = NULL,
                                                      .ctx_user_data = &ctx,
                                                      .ctx_state_changed_cb = basic_comch_state_changed_callback};

    /* Open DOCA device according to the given PCI address */
    result = open_doca_device_with_pci(config->comch_dev_pci_addr, NULL, &(ctx.hw_dev));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
        return result;
    }
    result = open_doca_device_rep_with_pci(ctx.hw_dev, DOCA_DEVINFO_REP_FILTER_NET, config->comch_dev_rep_pci_addr,
                                           &(ctx.rep_dev));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open DOCA device representor based on PCI address");
        return result;
    }

    result = init_comch_ctrl_path_server_with_ctx(g_server_name, ctx.hw_dev, ctx.rep_dev, &cb_cfg, &(ctx.server),
                                                  &(ctx.pe), &(ctx.ctx));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init cc client with error = %s", doca_error_get_name(result));
        return result;
    }
}

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

    run_server(&cfg);

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
