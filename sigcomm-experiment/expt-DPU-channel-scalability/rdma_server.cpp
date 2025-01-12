#include <cstdlib>
#include <ctime>
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
#include "doca_error.h"
#include "doca_pe.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"


DOCA_LOG_REGISTER(RDMA_SERVER::MAIN);


int skt_fd = 0;

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
    size_t expect_n_client;
    bool client_all_started;
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
void server_disconnection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                      struct doca_comch_connection *comch_conn, uint8_t change_success)
{

    (void)event;
    (void)change_success;
    struct doca_comch_server *comch_server = doca_comch_server_get_server_ctx(comch_conn);
    union doca_data data;

    doca_error_t result = doca_ctx_get_user_data(doca_comch_server_as_ctx(comch_server), &data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("get user data fail");
    }
    struct my_comch_ctx *user_data = (struct my_comch_ctx *)data.ptr;
    user_data->n_client_connected--;
    DOCA_LOG_INFO("client disconnected, %zu client remains", user_data->n_client_connected);
    if (user_data->n_client_connected == 0 && user_data->client_all_started)
    {
        doca_ctx_stop(user_data->ctx);
        DOCA_LOG_INFO("closing ctx");
    }
}
void server_connection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                         struct doca_comch_connection *comch_conn, uint8_t change_success)
{

    /* This argument is not in use */
    (void)event;
    (void)change_success;
    DOCA_LOG_INFO("client connected");
    struct doca_comch_server *comch_server = doca_comch_server_get_server_ctx(comch_conn);
    union doca_data data;

    // the connection user data have not been set
    doca_error_t result = doca_ctx_get_user_data(doca_comch_server_as_ctx(comch_server), &data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("get user data fail");
    }
    result = doca_comch_connection_set_user_data(comch_conn, data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("set connection user data fail");
    }
    struct my_comch_ctx *user_data = (struct my_comch_ctx *)data.ptr;
    user_data->n_client_connected++;
    DOCA_LOG_INFO("client connected, %zu client now", user_data->n_client_connected);
    if (user_data->n_client_connected == user_data->expect_n_client) {
        DOCA_LOG_INFO("all %zu client connected", user_data->n_client_connected);
        user_data->client_all_started = true;
    }
}
void server_message_recv_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer, uint32_t msg_len,
                                  struct doca_comch_connection *comch_connection)
{
    doca_error_t result;
    struct timespec start, end;
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct my_comch_ctx *sample_objects = (struct my_comch_ctx *)user_data.ptr;
    // struct doca_comch_client *comch_client = doca_comch_client_get_client_ctx(comch_connection);
    // save the connection for send back
    sample_objects->connection = comch_connection;
    struct doca_comch_task_send *task;

    /* This argument is not in use */
    (void)event;

    /* DOCA_LOG_INFO("Message received: '%.*s'", (int)msg_len, recv_buffer); */
    clock_gettime(CLOCK_TYPE_ID, &start);
    result = comch_server_send_msg(sample_objects->server, comch_connection, recv_buffer, msg_len, user_data, &task);
    clock_gettime(CLOCK_TYPE_ID, &end);
    // DOCA_LOG_INFO("send task requires %f", calculate_timediff_usec(&end, &start));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("failed to send pong");
    }
}
doca_error_t run_server(void *cfg)
{
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    memset(&resources, 0, sizeof(struct rdma_resources));

    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = new char [ MAX_RDMA_DESCRIPTOR_SZ ];

    doca_error_t result;
    struct comch_ctrl_path_server_cb_config cb_cfg = {.send_task_comp_cb = basic_send_task_completion_callback,
                                                      .send_task_comp_err_cb = basic_send_task_completion_err_callback,
                                                      .msg_recv_cb = server_message_recv_callback,
                                                      .server_connection_event_cb = server_connection_event_callback,
                                                      .server_disconnection_event_cb =
                                                          server_disconnection_event_callback,
                                                      .data_path_mode = false,
                                                      .new_consumer_cb = NULL,
                                                      .expired_consumer_cb = NULL,
                                                      .ctx_user_data = &ctx,
                                                      .ctx_state_changed_cb = server_comch_state_changed_callback};

    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    result = allocate_rdma_resources(cfg, mmap_permissions, rdma_permissions, doca_rdma_cap_task_receive_is_supported,
                                     &resources);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
    }

    result = init_comch_ctrl_path_server_with_ctx(g_server_name, ctx.hw_dev, ctx.rep_dev, &cb_cfg, &(ctx.server),
                                                  &(ctx.pe), &(ctx.ctx));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init cc client with error = %s", doca_error_get_name(result));
        return result;
    }

    while (ctx.finish != true)
    {
        doca_pe_progress(ctx.pe);
    }
    DOCA_LOG_INFO("processing finished");
}

int main(int argc, char **argv)
{
    struct rdma_config cfg;
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;

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

    result = register_rdma_common_params();
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
    char port[MAX_PORT_LEN];

    int_to_port_str(cfg.sock_port, port, MAX_PORT_LEN);

    std::string ip = "0.0.0.0";
    int fd = sock_utils_bind(ip.c_str(), port);
    if (fd < 0)
    {
        DOCA_LOG_ERR("sock fd fail");
        goto server_sock_error;
    }
    DOCA_LOG_INFO("start listen");
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    listen(fd, 5);
    skt_fd = accept(fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    DOCA_LOG_INFO("received connection: %d", skt_fd);

    run_server(&cfg);

    exit_status = EXIT_SUCCESS;

    close(skt_fd);
server_sock_error:
    close(fd);
argp_cleanup:
    doca_argp_destroy();
sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}
