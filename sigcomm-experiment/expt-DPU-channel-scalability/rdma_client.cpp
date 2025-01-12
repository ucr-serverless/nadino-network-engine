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
#include "doca_error.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"
#include "doca_ctx.h"
#include "sys/epoll.h"
#include "sock_utils.h"

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

const char *g_server_name = "comch_ctrl_path_sample_server";
const uint32_t n_thread = 512;
DOCA_LOG_REGISTER(RDMA_CLIENT::MAIN);


double g_latency = 0.0;
double g_rps = 0.0;
std::mutex g_mutex;

int skt_fd;

static void client_rdma_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    // the user data is the ctx userdata
    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    doca_error_t result;
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC client context has been stopped");
        /* We can stop progressing the PE */

        resources->run_pe_progress = false;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        // need to get the connection object first
        DOCA_LOG_INFO("client context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        if (clock_gettime(CLOCK_TYPE_ID, &resources->start_time) != 0)
        {
            DOCA_LOG_ERR("Failed to get timestamp");
        }
        DOCA_LOG_INFO("Start to establish RDMA connection ");
        /* Export RDMA connection details */
        result = doca_rdma_export(resources->rdma, &(resources->rdma_conn_descriptor),
                                  &(resources->rdma_conn_descriptor_size), &(resources->connections[0]));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to export RDMA: %s", doca_error_get_descr(result));
        }

        /* write and read connection details to the sender */
        /* result = write_read_connection(resources->cfg, resources, i); */
        {
            std::lock_guard<std::mutex> lock(g_mutex); // Automatically unlocks when out of scope
            result = sock_send_buffer(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size,
                                      skt_fd);
            if (result != DOCA_SUCCESS)
            {
                DOCA_LOG_ERR("Failed to send details from sender: %s", doca_error_get_descr(result));
            }
            result = sock_recv_buffer(resources->remote_rdma_conn_descriptor, &resources->remote_rdma_conn_descriptor_size,
                                      MAX_RDMA_DESCRIPTOR_SZ, skt_fd);
            if (result != DOCA_SUCCESS)
            {
                DOCA_LOG_ERR("Failed to recv details from sender: %s", doca_error_get_descr(result));
            }
            DOCA_LOG_INFO("exchanged RDMA info on ");
        }
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to get connection from client with error = %s", doca_error_get_name(result));
            (void)doca_ctx_stop(doca_rdma_as_ctx(resources->rdma));
        }
        result = doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor,
                                   resources->remote_rdma_conn_descriptor_size, resources->connections[0]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to connect the receiver's RDMA to the sender's RDMA: %s",
                         doca_error_get_descr(result));

            (void)doca_ctx_stop(doca_rdma_as_ctx(resources->rdma));

        }

        // TODO send receive request and submit send request
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

struct rdma_cb_config cb_cfg = {
    .send_imm_task_comp_cb = NULL,
    .send_imm_task_comp_err_cb = NULL,
    .msg_recv_cb = NULL,
    .msg_recv_err_cb = NULL,
    .data_path_mode = false,
    .ctx_user_data = NULL,
    .doca_rdma_connect_request_cb = NULL,
    .doca_rdma_connect_established_cb = NULL,
    .doca_rdma_connect_failure_cb = NULL,
    .doca_rdma_disconnect_cb = NULL,
    .state_change_cb = client_rdma_state_changed_callback,
};
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
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    memset(&resources, 0, sizeof(struct rdma_resources));

    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);

    doca_error_t result;
    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    // did not start ctx
    result = allocate_rdma_resources(config, mmap_permissions, rdma_permissions, doca_rdma_cap_task_receive_is_supported,
                                     &resources);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
    }


    result = init_send_imm_rdma_resources(&resources, config, &cb_cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init rdma client with error = %s", doca_error_get_name(result));
        return;
    }

    int ep_fd;
    if (config->is_epoll) {
        ep_fd = epoll_create1(0);
        if (ep_fd == -1)
        {
            DOCA_LOG_ERR("Failed to create epoll_fd");
        }
        result = register_pe_event(resources.pe, ep_fd);

        struct epoll_event ep_event
        {
        };
        int ret = 0;
        DOCA_LOG_INFO("epoll event loop");
        while (resources.run_pe_progress == true)
        {
            doca_pe_request_notification(resources.pe);
            ret = epoll_wait(ep_fd, &ep_event, 1, -1);
            if (ret == -1)
            {
                DOCA_LOG_ERR("failed to wait ep event");
            }
            doca_pe_clear_notification(resources.pe, 0);
            while (doca_pe_progress(resources.pe))
            {
            }
        }
    }
    else {

        while (resources.run_pe_progress == true)
        {
            doca_pe_progress(resources.pe);
        }
    }

    if (resources.remote_rdma_conn_descriptor != nullptr)
    {
        free( resources.remote_rdma_conn_descriptor );
    }

    double tt_time = calculate_timediff_usec(&resources.end_time, &resources.start_time);
    double rps = config->n_msg / tt_time * USEC_PER_SEC;
    DOCA_LOG_INFO("thread %d is running", id);
    {
        std::lock_guard<std::mutex> lock(g_mutex); // Automatically unlocks when out of scope
        g_rps += rps;
        g_latency += tt_time;
    }
    DOCA_LOG_INFO("Thread %d speed: %f usec", id, tt_time/ config->n_msg);
    DOCA_LOG_INFO("Thread %d rps: %f ", id, rps);

    destroy_rdma_resources(&resources, config);
    destroy_inventory(resources.buf_inventory);
}

void client_function(uint32_t num_threads, std::function<void(int, void *)> func, struct rdma_config *cfg)
{
    std::vector<std::thread> threads;

    // Create and run threads
    for (uint32_t i = 0; i < num_threads; ++i)
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
    result = doca_argp_init("rdma client", &cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register RDMA client sample parameters: %s", doca_error_get_descr(result));
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

    DOCA_LOG_INFO("start connect");
    skt_fd = sock_utils_connect(cfg.sock_ip, port);
    DOCA_LOG_INFO("connection established: %d", skt_fd);

    client_function(cfg.n_thread, run_clients, &cfg);

    DOCA_LOG_INFO("the latency is %f", g_latency);
    DOCA_LOG_INFO("the rps is %f", g_rps);

    exit_status = EXIT_SUCCESS;

    close(skt_fd);
argp_cleanup:
    doca_argp_destroy();
sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}
