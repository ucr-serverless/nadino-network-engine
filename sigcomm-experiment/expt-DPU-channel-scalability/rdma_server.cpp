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
#include "dma_common_doca.h"
#include "doca_buf.h"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "doca_error.h"
#include "doca_pe.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"
#include <unordered_map>
#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

DOCA_LOG_REGISTER(RDMA_SERVER::MAIN);

int skt_fd = 0;

std::unordered_map<struct doca_rdma_connection*, struct doca_buf*> conn_buf;
std::unordered_map<struct doca_buf*, struct doca_buf*> dpu_buf_to_host_buf;
std::unordered_map<struct doca_buf*, struct doca_buf*> dst_buf_to_src_buf;

// std::unordered_map<struct doca_rdma_connection*, std::pair<struct doca_buf*, struct doca_buf*>> conn_buf_pair;

void rdma_dma_memcpy_completed_callback(struct doca_dma_task_memcpy *dma_task, union doca_data task_user_data,
                                         union doca_data ctx_user_data)
{
    doca_error_t result = DOCA_SUCCESS;
    struct doca_rdma_connection *conn = (struct doca_rdma_connection *)task_user_data.ptr;

    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;

    /* Assign success to the result */
    DOCA_LOG_INFO("DMA task was completed successfully");

    /* Free task */
    struct doca_rdma_task_send_imm *send_task;
    doca_task_free(doca_dma_task_memcpy_as_task(dma_task));
    result = submit_send_imm_task(resources->rdma, conn, conn_buf[conn], 0, task_user_data, &send_task);
    LOG_ON_FAILURE(result);
}

void server_rdma_recv_then_send_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{

    // DOCA_LOG_INFO("message received");
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    doca_error_t result;
    struct doca_rdma_task_send_imm *send_task;

    const struct doca_rdma_connection *conn = doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);

    struct doca_rdma_connection *rdma_connection = (struct doca_rdma_connection *)conn;

    // auto [src_buf, dst_buf] = conn_buf_pair[rdma_connection];
    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get src buf fail");
    }
    auto src_buf = dst_buf_to_src_buf[buf];

    // DOCA_LOG_INFO("the get ptr %p, the ptr in map %p", buf, dst_buf);
    doca_buf_reset_data_len(buf);
    // print_doca_buf_len(buf);

    // resubmit tasks
    result = doca_task_submit(doca_rdma_task_receive_as_task(rdma_receive_task));
    JUMP_ON_DOCA_ERROR(result, free_task);

    result = submit_send_imm_task(resources->rdma, rdma_connection, src_buf, 0, task_user_data, &send_task);
    JUMP_ON_DOCA_ERROR(result, free_task);
    return;

free_task:
    result = doca_buf_dec_refcount(buf, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }
    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));
}

void rdma_recv_then_dma(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{

    DOCA_LOG_INFO("message received");
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    doca_error_t result;

    (void)task_user_data;
    const struct doca_rdma_connection *conn = doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);

    struct doca_rdma_connection *rdma_connection = (struct doca_rdma_connection *)conn;

    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get src buf fail");
    }
    conn_buf[rdma_connection] = buf;

    doca_buf_reset_data_len(buf);

    // resubmit tasks
    result = doca_task_submit(doca_rdma_task_receive_as_task(rdma_receive_task));
    JUMP_ON_DOCA_ERROR(result, free_task);

    union doca_data task_data;
    task_data.ptr = rdma_connection;
    struct doca_dma_task_memcpy *dma_task;
    result = submit_dma_task(resources->dma_res.dma, buf, dpu_buf_to_host_buf[buf], task_data, &dma_task);
    JUMP_ON_DOCA_ERROR(result, free_task);
    return;

free_task:
    result = doca_buf_dec_refcount(buf, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }
    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));
}

static doca_error_t rdma_multi_conn_send_prepare_and_submit_task(struct rdma_resources *resources)
{
    struct doca_rdma_task_receive *rdma_recv_tasks[MAX_NUM_CONNECTIONS] = {0};
    union doca_data task_user_data = {0};
    struct doca_buf *src_bufs[MAX_NUM_CONNECTIONS] = {0};
    struct doca_buf *dst_bufs[MAX_NUM_CONNECTIONS] = {0};
    struct doca_buf *host_bufs[MAX_NUM_CONNECTIONS] = {0};
    doca_error_t result, tmp_result;
    uint32_t i = 0;
    struct doca_mmap *dst_mmap = NULL;
    char *start_addr = NULL;

    task_user_data.ptr = resources;
    for (i = 0; i < resources->cfg->n_thread; i++)
    {
        /* Add src buffer to DOCA buffer inventory */

        // off path mode directly write to host
        if (resources->cfg->is_host_export == true && resources->cfg->on_path == false) {
            assert(resources->cfg->host_mmap != NULL);
            dst_mmap = resources->cfg->host_mmap;
            start_addr = (char*)resources->cfg->host_buf_addr;
        }
        else
        {
            dst_mmap = resources->mmap;
            start_addr = resources->mmap_memrange;
        }
        // result = doca_buf_inventory_buf_get_by_data(resources->buf_inventory, dst_mmap,
        //                                             start_addr + i * resources->cfg->msg_sz, resources->cfg->msg_sz,
        //                                             &src_bufs[i]);
        result = get_buf_from_inv_with_full_data_len(resources->buf_inventory, dst_mmap, start_addr + i * resources->cfg->msg_sz, resources->cfg->msg_sz, &src_bufs[i]);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to allocate DOCA buffer [%d] to DOCA buffer inventory: %s", i,
                         doca_error_get_descr(result));
            return result;
        }
        result = get_buf_from_inv_with_zero_data_len(resources->buf_inventory, dst_mmap, start_addr + i * resources->cfg->msg_sz, resources->cfg->msg_sz, &dst_bufs[i]);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to allocate DOCA buffer [%d] to DOCA buffer inventory: %s", i,
                         doca_error_get_descr(result));
            return result;
        }
        // print_doca_buf_len(src_bufs[i]);
        // conn_buf_pair[resources->connections[i]] = std::make_pair(src_bufs[i], dst_bufs[i]);
        dst_buf_to_src_buf[dst_bufs[i]] = src_bufs[i];


        result = submit_recv_task(resources->rdma, dst_bufs[i], task_user_data, &rdma_recv_tasks[i]);
        JUMP_ON_DOCA_ERROR(result, destroy_src_buf);
        if (resources->cfg->is_host_export == true && resources->cfg->on_path == false) {
            result = get_buf_from_inv_with_zero_data_len(resources->dma_res.inv, resources->cfg->host_mmap,
                                                        (char*)resources->cfg->host_buf_addr + i * resources->cfg->msg_sz, resources->cfg->msg_sz,
                                                        &host_bufs[i]);
            if (result != DOCA_SUCCESS)
            {
                DOCA_LOG_ERR("Failed to allocate DOCA buffer [%d] to DOCA buffer inventory: %s", i,
                             doca_error_get_descr(result));
                return result;
            }
            dpu_buf_to_host_buf[src_bufs[i]] = host_bufs[i];

        }
    }
    return result;
destroy_src_buf:
    tmp_result = doca_buf_dec_refcount(src_bufs[i], NULL);
    if (tmp_result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease src_buf count: %s", doca_error_get_descr(tmp_result));
        DOCA_ERROR_PROPAGATE(result, tmp_result);
    }
    return result;
}

static void server_rdma_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                               enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    doca_error_t result;
    char started = '1';
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC server context has been stopped");
        /* We can stop progressing the PE */

        resources->run_pe_progress = false;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        DOCA_LOG_ERR("server context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA server context is running. Waiting for clients to connect");
        result = rdma_multi_conn_recv_export_and_connect(resources, resources->connections, resources->cfg->n_thread,
                                                         resources->cfg->sock_fd);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_INFO("multiple connection error");
        }
        result = init_inventory(&resources->buf_inventory, resources->cfg->n_thread * 2);
        JUMP_ON_DOCA_ERROR(result, error);

        result = rdma_multi_conn_send_prepare_and_submit_task(resources);
        JUMP_ON_DOCA_ERROR(result, error);
        // send start signal

        DOCA_LOG_INFO("sent start signal");
        sock_utils_write(resources->cfg->sock_fd, &started, sizeof(char));


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
    return;

error:
    DOCA_LOG_INFO("ctx change error");
    doca_ctx_stop(ctx);
    destroy_inventory(resources->buf_inventory);
    destroy_rdma_resources(resources, resources->cfg);
    
}
doca_error_t run_server(void *cfg)
{
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    memset(&resources, 0, sizeof(struct rdma_resources));
    resources.cfg = config;
    resources.cfg->sock_fd = skt_fd;

    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);

    doca_error_t result;
    struct rdma_cb_config cb_cfg = {
        .send_imm_task_comp_cb = basic_send_imm_completed_callback,
        .send_imm_task_comp_err_cb = basic_send_imm_completed_err_callback,
        .msg_recv_cb = server_rdma_recv_then_send_callback,
        .msg_recv_err_cb = rdma_recv_err_callback,
        .data_path_mode = false,
        .ctx_user_data = &resources,
        .doca_rdma_connect_request_cb = basic_rdma_connection_callback,
        .doca_rdma_connect_established_cb = basic_rdma_connection_established_callback,
        .doca_rdma_connect_failure_cb = basic_rdma_connection_failure,
        .doca_rdma_disconnect_cb = basic_rdma_disconnect_callback,
        .state_change_cb = server_rdma_state_changed_callback,
    };
    struct dma_cb dma_cb_cfg = {
        .ctx_data = &resources,
        .task_completion_cb = rdma_dma_memcpy_completed_callback,
        .task_error_cb = basic_dma_memcpy_error_callback,
        .state_change_cb = NULL,
        .n_task = 0,
    };
    if (resources.cfg->is_host_export == true && resources.cfg->on_path == false) {
        cb_cfg.msg_recv_cb = rdma_recv_then_dma;
    }

    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    result =
        allocate_rdma_resources(config, mmap_permissions, rdma_permissions, doca_rdma_cap_task_receive_is_supported,
                                &resources, 2 * config->n_thread * config->msg_sz, config->n_thread);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
    }

    // add the host exported mmap
    if (config->is_host_export == true && (config->host_descriptor != NULL))
    {

        DOCA_LOG_INFO("import from host");
        result = doca_mmap_create_from_export(NULL, (const void *)config->host_descriptor, config->host_descriptor_size,
                                              resources.doca_device, &config->host_mmap);

        JUMP_ON_DOCA_ERROR(result, error);
        DOCA_LOG_INFO("import buffer success");
    }

    result = init_send_imm_rdma_resources(&resources, config, &cb_cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init rdma server with error = %s", doca_error_get_name(result));
        return result;
    }
    DOCA_LOG_INFO("ctx started");

    if (resources.cfg->is_host_export == true && resources.cfg->on_path == false) {
        result =  allocate_dma_with_rdma_dev(&resources, &dma_cb_cfg);
        LOG_ON_FAILURE(result);

    }

    while (resources.run_pe_progress == true)
    {
        doca_pe_progress(resources.pe);
    }
    DOCA_LOG_INFO("processing finished");
    return DOCA_SUCCESS;
error:
    return result;
}

int main(int argc, char **argv)
{
    struct rdma_config cfg;
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;
    char port[MAX_PORT_LEN];
    int fd;
    struct sockaddr_in peer_addr;
    const char *ip = "0.0.0.0";
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);

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

    int_to_port_str(cfg.sock_port, port, MAX_PORT_LEN);

    fd = sock_utils_bind(const_cast<char *>(ip), port);
    if (fd < 0)
    {
        DOCA_LOG_ERR("sock fd fail");
        goto server_sock_error;
    }
    DOCA_LOG_INFO("start listen");
    listen(fd, 5);

    if (cfg.is_host_export == true)
    {
        DOCA_LOG_INFO("start receive host buffer");
        skt_fd = accept(fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        result = sock_recv_buffer(cfg.host_descriptor, &cfg.host_descriptor_size, MAX_RDMA_DESCRIPTOR_SZ, cfg.sock_fd);
        JUMP_ON_DOCA_ERROR(result, close_skt_fd);

        result = sock_recv_ptr(&cfg.host_buf_addr, cfg.sock_fd);
        JUMP_ON_DOCA_ERROR(result, close_skt_fd);

        result = sock_recv_range(&cfg.host_buf_range, cfg.sock_fd);
        JUMP_ON_DOCA_ERROR(result, close_skt_fd);
        print_buffer_hex(cfg.host_descriptor, cfg.host_descriptor_size);
        if (cfg.host_buf_range < cfg.n_thread * cfg.msg_sz) {
            DOCA_LOG_ERR("host export is too small");
            goto close_skt_fd;
        }
        // close the skt connection with host and connect with the rdma_client
        DOCA_LOG_INFO("end receive host buffer");
        close(skt_fd);
    }
    // connect the host first if there is need
    skt_fd = accept(fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    DOCA_LOG_INFO("server received skt connection: %d", skt_fd);


    run_server(&cfg);

    exit_status = EXIT_SUCCESS;

close_skt_fd:
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
