#include <cstdlib>
#include <functional>
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <cstring>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <iostream>
#include <mutex>
#include <vector>

#include "comch_ctrl_path_common.h"
#include "comch_utils.h"
#include "common_doca.h"
#include "doca_buf.h"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "doca_error.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"
#include "sys/epoll.h"

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

const char *g_server_name = "comch_ctrl_path_sample_server";
const uint32_t n_thread = 512;
DOCA_LOG_REGISTER(RDMA_CLIENT::MAIN);

double g_latency = 0.0;
double g_rps = 0.0;
std::mutex g_mutex;
size_t connections = 0;

int skt_fd;

void client_rdma_recv_then_send_callback(struct doca_rdma_task_receive *rdma_receive_task,
                                         union doca_data task_user_data, union doca_data ctx_user_data)
{
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    doca_error_t result;
    struct doca_rdma_connection *rdma_connection;
    struct doca_rdma_task_send_imm *send_task;

    rdma_connection =
        (struct doca_rdma_connection *)doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);

    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);

    // it is the resources->dst_buf
    doca_buf_reset_data_len(buf);

    resources->n_received_req++;

    if (resources->n_received_req < resources->cfg->n_msg)
    {
        result = doca_task_submit(doca_rdma_task_receive_as_task(rdma_receive_task));
        JUMP_ON_DOCA_ERROR(result, free_task);

        result = submit_send_imm_task(resources->rdma, rdma_connection, resources->src_buf, 0, task_user_data, &send_task);
        JUMP_ON_DOCA_ERROR(result, free_task);
        return;
    }
    if (clock_gettime(CLOCK_TYPE_ID, &resources->end_time) != 0)
    {
        DOCA_LOG_ERR("Failed to get timestamp");
    }
free_task:
    result = doca_buf_dec_refcount(buf, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }
    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));
    DOCA_LOG_INFO("thread %d finished", resources->id);
    doca_ctx_stop(resources->rdma_ctx);
}

static doca_error_t local_rdma_conn_recv_and_send(struct rdma_resources* resources) {
    doca_error_t result;
    std::chrono::nanoseconds duration(500);
    struct doca_rdma_task_receive *rdma_recv_task;
    struct doca_rdma_task_send_imm *rdma_send_task;

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
        result = sock_send_buffer(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size, skt_fd);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to send details from sender: %s", doca_error_get_descr(result));
        }
        result = sock_recv_buffer(resources->remote_rdma_conn_descriptor,
                                  &resources->remote_rdma_conn_descriptor_size, MAX_RDMA_DESCRIPTOR_SZ, skt_fd);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to recv details from sender: %s", doca_error_get_descr(result));
        }
        DOCA_LOG_INFO("exchanged RDMA info on [%d]", resources->id);
        connections++;
    }

    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to get connection from client with error = %s", doca_error_get_name(result));
        (void)doca_ctx_stop(doca_rdma_as_ctx(resources->rdma));
    }

    result = doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor,
                               resources->remote_rdma_conn_descriptor_size, resources->connections[0]);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to connect the receiver's RDMA to the sender's RDMA: %s",
                     doca_error_get_descr(result));

        (void)doca_ctx_stop(doca_rdma_as_ctx(resources->rdma));
    }

    result = init_inventory(&resources->buf_inventory, 5);
    JUMP_ON_DOCA_ERROR(result, error);

    // TODO send receive request and submit send request
    DOCA_LOG_INFO("RDMA client context is running");

    result = get_buf_from_inv_with_full_data_len(resources->buf_inventory, resources->mmap,
                                                resources->mmap_memrange, resources->cfg->msg_sz,
                                                &resources->src_buf);
    if (result != DOCA_SUCCESS)
    {
        LOG_ON_FAILURE(result);
        return result;
    }
    // print_doca_buf_len(resources->src_buf);
    result = get_buf_from_inv_with_zero_data_len(resources->buf_inventory, resources->mmap,
                                                resources->mmap_memrange + resources->cfg->msg_sz, resources->cfg->msg_sz,
                                                &resources->dst_buf);
    if (result != DOCA_SUCCESS)
    {
        LOG_ON_FAILURE(result);
        return result;
    }
    // print_doca_buf_len(resources->dst_buf);

    DOCA_LOG_INFO("wait for start signal");

    while (resources->cfg->is_perf_started == false){
        std::this_thread::sleep_for(duration);
    }

    DOCA_LOG_INFO("[%d] thread get start signal", resources->id);

    union doca_data task_user_data;
    task_user_data.ptr = &resources->first_encountered_error;


    result = submit_recv_task(resources->rdma, resources->dst_buf, task_user_data, &rdma_recv_task);
    LOG_ON_FAILURE(result);


    /* Allocate and construct RDMA send task */
    if (clock_gettime(CLOCK_TYPE_ID, &resources->start_time) != 0)
    {
        DOCA_LOG_ERR("Failed to get timestamp");
    }
    void *src_data;
    
    result = doca_buf_get_data(resources->src_buf, &src_data);
    LOG_ON_FAILURE(result);
    strncpy((char*)src_data, "hello", resources->cfg->msg_sz);
    // printf("%s\n", (char*)src_data);

    result = submit_send_imm_task(resources->rdma, resources->connections[0], resources->src_buf, 0, task_user_data,
                                  &rdma_send_task);
    LOG_ON_FAILURE(result);
error:
    return result;
};
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

        result = local_rdma_conn_recv_and_send(resources);
        LOG_ON_FAILURE(result);
        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        doca_buf_dec_refcount(resources->dst_buf, NULL);
        DOCA_LOG_INFO("client context entered into stopping state");
        break;
    default:
        break;
    }
}

void run_clients(int id, void *cfg)
{
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    resources.id = id;
    memset(&resources, 0, sizeof(struct rdma_resources));

    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);
    resources.cfg = config;

    struct rdma_cb_config cb_cfg = {
        .send_imm_task_comp_cb = basic_send_imm_completed_callback,
        .send_imm_task_comp_err_cb = basic_send_imm_completed_err_callback,
        .msg_recv_cb = client_rdma_recv_then_send_callback,
        .msg_recv_err_cb = rdma_recv_err_callback,
        .data_path_mode = false,
        .ctx_user_data = &resources,
        .doca_rdma_connect_request_cb = basic_rdma_connection_callback,
        .doca_rdma_connect_established_cb = basic_rdma_connection_established_callback,
        .doca_rdma_connect_failure_cb = basic_rdma_connection_failure,
        .doca_rdma_disconnect_cb = basic_rdma_disconnect_callback,
        .state_change_cb = client_rdma_state_changed_callback,
    };
    doca_error_t result;
    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    // did not start ctx
    result = allocate_rdma_resources(config, mmap_permissions, rdma_permissions,
                                     doca_rdma_cap_task_receive_is_supported, &resources, config->msg_sz * 2, config->n_thread);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
        return;
    }

    result = init_send_imm_rdma_resources(&resources, config, &cb_cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init rdma client with error = %s", doca_error_get_name(result));
        return;
    }
    DOCA_LOG_INFO("thread [%d] ctx started", id);

    int ep_fd;
    if (config->is_epoll)
    {
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
    else
    {

        while (resources.run_pe_progress == true)
        {
            doca_pe_progress(resources.pe);
        }
    }

    double tt_time = calculate_timediff_usec(&resources.end_time, &resources.start_time);
    double rps = config->n_msg / tt_time * USEC_PER_SEC;
    DOCA_LOG_INFO("thread %d is running", id);
    {
        std::lock_guard<std::mutex> lock(g_mutex); // Automatically unlocks when out of scope
        g_rps += rps;
        g_latency += tt_time;
    }
    DOCA_LOG_INFO("Thread %d speed: %f usec", id, tt_time / config->n_msg);
    DOCA_LOG_INFO("Thread %d rps: %f ", id, rps);

    destroy_inventory(resources.buf_inventory);
    destroy_rdma_resources(&resources, config);
}

void client_function(uint32_t num_threads, std::function<void(int, void *)> func, struct rdma_config *cfg)
{
    std::vector<std::thread> threads;
    std::chrono::nanoseconds duration(500);

    // Create and run threads
    for (uint32_t i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(func, i, (void *)cfg); // Pass thread index to function
    }

    char started;

    // busy wait for all qp to be connected
    while(connections < num_threads) {
        std::this_thread::sleep_for(duration);
    }

    DOCA_LOG_INFO("all threads connected");
    sock_utils_read(skt_fd, &started, sizeof(char));

    DOCA_LOG_INFO("waiting for start signal");
    if (started == '1') {
        cfg->is_perf_started = true;
    }
    DOCA_LOG_INFO("received start signal");

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
    set_default_config_value(&cfg);

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
