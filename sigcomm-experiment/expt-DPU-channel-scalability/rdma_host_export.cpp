#include <stdlib.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <sys/types.h>

#include "common_doca.h"
#include "doca_error.h"
#include "doca_rdma.h"
#include "log.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"

DOCA_LOG_REGISTER(HOST_EXPORT_MAIN::MAIN);

#define BUF_SZ 4096
#define MAX_EXPT_BUF_SZ 1024
struct host_resources
{
    struct rdma_config *cfg;
    struct doca_dev *doca_device; /* DOCA device */
    struct doca_pe *pe;           /* DOCA progress engine */
    struct doca_mmap *buf_mmap;   /* DOCA memory map */
    size_t buf_sz;
    char *buf;
    uint8_t export_descriptor[MAX_EXPT_BUF_SZ];
    size_t export_descriptor_size;
};

doca_error_t allocate_rdma_copy_resources(struct host_resources *resources, struct rdma_config *cfg)
{
    doca_error_t result;

    resources->cfg = cfg;
    /* Open DOCA device */
    result = open_doca_device_with_ibdev_str(cfg->device_name, doca_rdma_cap_task_receive_is_supported,
                                             &(resources->doca_device));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open DOCA device: %s", doca_error_get_descr(result));
        return result;
    }

    resources->buf_sz = cfg->n_thread * cfg->msg_sz * 2;

    result = create_doca_mmap_from_buf(&resources->buf_mmap, resources->buf_sz, DOCA_ACCESS_FLAG_PCI_READ_WRITE,
                                       resources->doca_device, &resources->buf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to allocate recv buffer: %s", doca_error_get_descr(result));
        return DOCA_ERROR_NO_MEMORY;
    }
    DOCA_LOG_INFO("The content of the buffer is %.4096s", resources->buf);
    *(resources->buf + cfg->msg_sz) = '1';

    return result;
}
int main(int argc, char **argv)
{
    struct rdma_config cfg;
    struct host_resources resources = {0};
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;
    const void *export_descriptor_ptr = NULL;
    /* Set the default configuration values (Example values) */
    result = set_default_config_value(&cfg);
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    /* No need for send_string in the receiver side */
    cfg.send_string[0] = '\0';

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

    /* Initialize argparser */
    result = doca_argp_init("doca_rdma_multi_conn_receive", &cfg);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    /* Register RDMA common params */
    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Start argparser */
    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    result = allocate_rdma_copy_resources(&resources, &cfg);
    JUMP_ON_DOCA_ERROR(result, error);

    export_descriptor_ptr = (void *)resources.export_descriptor;
    result = doca_mmap_export_pci(resources.buf_mmap, resources.doca_device, &export_descriptor_ptr,
                                  &resources.export_descriptor_size);
    JUMP_ON_DOCA_ERROR(result, error);

    print_buffer_hex(export_descriptor_ptr, resources.export_descriptor_size);

    /* char port[MAX_PORT_LEN]; */
    /**/
    /* int_to_port_str(cfg.sock_port, port, MAX_PORT_LEN); */

    log_info("start connect");
    char port[MAX_PORT_LEN];
    int_to_port_str(cfg.sock_port, port, MAX_PORT_LEN);

    cfg.sock_fd = sock_utils_connect(cfg.sock_ip, port);
    log_info("connection established: %d", cfg.sock_fd);
    JUMP_ON_FAILURE_CONDITION((cfg.sock_fd < 0), error, "create socket fail");

    result = sock_send_buffer(export_descriptor_ptr, resources.export_descriptor_size, cfg.sock_fd);
    JUMP_ON_DOCA_ERROR(result, error);

    result = sock_send_ptr((uint64_t)resources.buf, cfg.sock_fd);
    JUMP_ON_DOCA_ERROR(result, error);

    result = sock_send_range(resources.buf_sz, cfg.sock_fd);
    JUMP_ON_DOCA_ERROR(result, error);

    DOCA_LOG_INFO("please press endter to contine");
    wait_for_enter();
    DOCA_LOG_INFO("The content of mmap: %s", (char *)resources.buf);
    DOCA_LOG_INFO("The content of mmap: %s", (char *)resources.buf + cfg.msg_sz);
    DOCA_LOG_INFO("please press endter to contine");
    wait_for_enter();
    DOCA_LOG_INFO("The content of mmap: %s", (char *)resources.buf);

    exit_status = EXIT_SUCCESS;
error:
    close(cfg.sock_fd);
argp_cleanup:
    doca_argp_destroy();
sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}
