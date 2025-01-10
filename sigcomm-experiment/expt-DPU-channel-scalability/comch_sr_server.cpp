#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>
#include <functional>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <stdbool.h>
#include <vector>
#include <iostream>
#include <mutex>

#include "comch_ctrl_path_common.h"
#include "common_doca.h"
#include "comch_utils.h"

#define DEFAULT_PCI_ADDR "b1:00.0"
#define DEFAULT_MESSAGE "Message from the client"

const char *g_server_name = "comch_ctrl_path_sample_server";
const uint32_t n_thread = 512;
DOCA_LOG_REGISTER(COMCH_CLIENT::MAIN);


uint64_t g_latency = 0;
double g_rps = 0.0;
std::mutex g_mutex;
struct my_comch_ctx
{
    struct doca_dev *hw_dev;                  /* Device used in the sample */
    struct doca_pe *pe;                       /* PE object used in the sample */
    struct doca_comch_client *client;         /* Client object used in the sample */
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
};
void sample_task(int id, void* cfg) {
    struct comch_config *config = (struct comch_config*)cfg;
    struct my_comch_ctx ctx;
    memset(&ctx, 0, sizeof(struct my_comch_ctx));

    doca_error_t result;
    struct comch_ctrl_path_client_cb_config cb_cfg = {.send_task_comp_cb = basic_send_task_completion_callback,
                                                   .send_task_comp_err_cb = basic_send_task_completion_err_callback,
                                                   .msg_recv_cb = NULL,
                                                   .data_path_mode = false,
                                                   .new_consumer_cb = NULL,
                                                   .expired_consumer_cb = NULL,
                                                   .ctx_user_data = &ctx,
                                                   .ctx_state_changed_cb = NULL};

    /* Open DOCA device according to the given PCI address */
    result = open_doca_device_with_pci(config->comch_dev_pci_addr, NULL, &(ctx.hw_dev));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
        return;
    }

    result = init_comch_ctrl_path_client(g_server_name, ctx.hw_dev, &cb_cfg, &(ctx.client),
                                         &(ctx.pe));
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init cc client with error = %s", doca_error_get_name(result));
        return;
    }

    return;
    std::cout << "Thread " << id << " is running.\n";
    {
        std::lock_guard<std::mutex> lock(g_mutex);  // Automatically unlocks when out of scope
        g_latency += 1;
        std::cout << "Thread " << id << " updated shared_value to: " << g_latency << "\n";
    }
}

void client_function(int num_threads, std::function<void(int, void*)> func, struct comch_config* cfg) {
    std::vector<std::thread> threads;

    // Create and run threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(func, i, (void*)cfg);  // Pass thread index to function
    }

    // Join threads to wait for completion
    for (auto& t : threads) {
        if (t.joinable()) {
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

    client_function(20, sample_task, &cfg);

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
