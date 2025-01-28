#include "palladium_nf_common.h"
#include "comch_ctrl_path_common.h"
#include "common_doca.h"
#include "doca_pe.h"
#include "http.h"
#include "io.h"
#include "log.h"
#include "palladium_doca_common.h"
#include "rte_branch_prediction.h"
#include "spright.h"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <netinet/in.h>
#include <ratio>
#include <stdexcept>
#include <sys/epoll.h>
#include <nlohmann/json.hpp>
#include <thread>

using json = nlohmann::json;

DOCA_LOG_REGISTER(PALLADIUM_NF::COMMON);
using namespace std;

void expt_settings::print_settings()
{
    cout << "batch size " << this->batch_sz << endl;
    cout << "sleep time" << this->sleep_time << endl;

}

void expt_settings::read_from_json(json& data, uint32_t nf_id)
{
    try {
        string id = to_string(nf_id);
        if (data.contains(id) && data[id].is_object()) {
            this->batch_sz = data[id]["batch_sz"];
            this->sleep_time = data[id]["sleep_time"];
            this->bf_mode = data[nf_id]["nf_mode"];
        } else {
            std::cerr << "Error: ID " << nf_id << " not found in the JSON file." << std::endl;
        }

    } catch (const std::exception& e) {
        log_error("json parsing not valid %s", e.what());
    }
}

nf_ctx::nf_ctx(struct spright_cfg_s *cfg, uint32_t nf_id) : gateway_ctx(cfg), nf_id(nf_id) {
    this->n_worker = cfg->nf[nf_id - 1].n_threads;
    this->ing_port = 8090 + nf_id;
    this->expected_pkt = cfg->n_msg;
    this->received_pkg = 0;
    this->json_data = read_json_from_file(std::string(cfg->json_path));
    std::cout << this->json_data.dump(4);
    this->expt_setting.read_from_json(this->json_data, nf_id);

};
void nf_ctx::print_nf_ctx() {
    cout << endl;
    std::cout << "nf_id: " << nf_id << "\n";
    std::cout << "comch_client: " << comch_client << "\n";
    std::cout << "comch_conn: " << comch_conn << "\n";
    std::cout << "comch_client_ctx: " << comch_client_ctx << "\n";
    std::cout << "comch_client_pe: " << comch_client_pe << "\n";
    std::cout << "comch_client_dev: " << comch_client_dev << "\n";
    std::cout << "current_worker: " << static_cast<int>(current_worker) << "\n";
    std::cout << "n_worker: " << static_cast<int>(n_worker) << "\n";
    std::cout << "inter_fn_skt: " << inter_fn_skt << "\n";
    std::cout << "rx_ep_fd: " << rx_ep_fd << "\n";
    std::cout << "comch_client_cb: " << &comch_client_cb << "\n";
    std::cout << "tx_rx_event_fd: " << tx_rx_event_fd << "\n";
    std::cout << "ing_fd: " << ing_fd << "\n";
    std::cout << "ing_port: " << ing_port << "\n";

    std::cout << "routes_start_from_nf: ";
    for (const auto& route : routes_start_from_nf) {
        std::cout << route << " ";
    }
    std::cout << "\n";

    cout<< "nf_id: " << this->nf_id << endl;
    
    this->expt_setting.print_settings();

}



void generate_pkt(struct nf_ctx *n_ctx, void** txn)
{
    log_debug("generate pkt");
    int ret = 0;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    uint32_t tenant_id = n_res.tenant_id;
    auto &t_res = n_ctx->tenant_id_to_res[tenant_id];

    ret = rte_mempool_get(t_res.mp_ptr, txn);
    while(ret != 0) {
        ret = rte_mempool_get(t_res.mp_ptr, txn);
        log_warn("generate pkt try to get buf");
    }
    RUNTIME_ERROR_ON_FAIL(ret != 0, "get element fail");
    uint64_t p = reinterpret_cast<uint64_t>(*txn);
    log_debug("the txn addr: %p, %lu", txn, p);
    struct http_transaction *pkt = (struct http_transaction*)*txn;
    pkt->tenant_id = tenant_id;
    pkt->route_id = n_ctx->routes_start_from_nf[0];
    // skip the initial processing of the first function
    pkt->hop_count = 0;
    // thr route should not be only only one function
    pkt->next_fn = n_ctx->nf_id;
    pkt->nf_get = 1;
}

void *basic_nf_tx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    struct http_transaction *txn = NULL;
    ssize_t bytes_read;
    doca_error_t result;
    union doca_data user_data;
    uint8_t i;
    int n_fds;
    int epfd;
    int ret;
    uint64_t flag_to_send;

    struct doca_comch_task_send *task;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    uint32_t tenant_id = n_res.tenant_id;
    auto& t_res = n_ctx->tenant_id_to_res[tenant_id];

    user_data.u64 = reinterpret_cast<uint64_t>(n_ctx);

    epfd = epoll_create1(0);
    if (unlikely(epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return NULL;
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = set_nonblocking(n_ctx->pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            return NULL;
        }

        event[0].events = EPOLLIN;
        event[0].data.fd = n_ctx->pipefd_tx[i][0];

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, n_ctx->pipefd_tx[i][0], &event[0]);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return NULL;
        }
    }
    if(n_ctx->wait_point) {
        n_ctx->wait_point->wait();
    }
    log_debug("now not wait");
    n_ctx->print_nf_ctx();

    if (n_res.nf_mode == ACTIVE_SEND) {

        struct http_transaction *txn = nullptr;
        void *tmp = (void*)txn;
        generate_pkt(n_ctx, &tmp);
        ret = write_to_worker(n_ctx, tmp);
        if (unlikely(ret == -1)) {
            log_error("write to workder error");
        }
        log_info("send first packet");
        
        if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->start) != 0)
        {
            DOCA_LOG_ERR("Failed to get timestamp");
        }

    }
    
    while (1)
    {
        n_fds = epoll_wait(epfd, event, cfg->nf[n_ctx->nf_id - 1].n_threads, 0);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (i = 0; i < n_fds; i++)
        {
            bytes_read = read(event[i].data.fd, &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_read == -1))
            {
                log_error("read() error: %s", strerror(errno));
                return NULL;
            }

            txn->hop_count++;

            if (likely(txn->hop_count < cfg->route[txn->route_id].length))
            {
                txn->next_fn = cfg->route[txn->route_id].hop[txn->hop_count];
            }
            else
            {
                // TODO: add comch here when reached an end
                txn->next_fn = 0;
                if (n_res.nf_mode == ACTIVE_SEND) {
                    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u) finished!!!!",
                      txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
                      txn->caller_nf, txn->caller_fn, txn->rpc_handler);
                    n_ctx->received_pkg++;
                    if (n_ctx->received_pkg < n_ctx->expected_pkt) {
                        int bytes_written = write(n_ctx->tx_rx_pp[1], &flag_to_send, sizeof(uint64_t));
                        if (unlikely(bytes_written == -1))
                        {
                            log_error("write() error: %s", strerror(errno));
                        }
                    }
                    else {
                        if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->end) != 0)
                        {
                            DOCA_LOG_ERR("Failed to get timestamp");
                        }
                        double tt_time = calculate_timediff_usec(&n_ctx->end, &n_ctx->start);
                        double rps = n_ctx->expected_pkt / tt_time * USEC_PER_SEC;
                        log_info("nf %d speed: %f usec", n_ctx->nf_id, tt_time / n_ctx->expected_pkt);
                        log_info("nf rps: %f ", rps);
                    }
                    log_debug("finish [%d] msg", n_ctx->received_pkg);

                    log_debug("nf get it");
                    // totally safe event if release ptr get by gateway
                    rte_mempool_put(t_res.mp_ptr, txn);

                    continue;
                }
            }

            log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
                      txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
                      txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            if (is_gtw_on_dpu(n_ctx->p_mode)) {
                uint32_t next_fn_node = n_ctx->fn_id_to_res[txn->next_fn].node_id;
                if (next_fn_node != n_ctx->node_id || txn->next_fn == 0) {
                    log_debug("send ptr %lu", reinterpret_cast<uint64_t>(txn));
                    struct comch_msg msg(reinterpret_cast<uint64_t>(txn), txn->next_fn, txn->ing_id);
                    result = comch_client_send_msg_retry(n_ctx->comch_client, n_ctx->comch_conn, (void*)&msg, sizeof(struct comch_msg), user_data, &task);
                    LOG_AND_FAIL(result);
                    continue;
                }
            }
            ret = new_io_tx(n_ctx->nf_id, txn, txn->next_fn);
            if (unlikely(ret == -1))
            {
                log_error("io_tx() error");
                return NULL;
            }
        }
    }

    return NULL;
}
int write_to_worker(struct nf_ctx *n_ctx, void* txn)
{
    log_debug("write to worker");
    int bytes_written;
    bytes_written = write(n_ctx->pipefd_rx[n_ctx->current_worker][1], &txn, sizeof(struct http_transaction *));
    if (unlikely(bytes_written == -1))
    {
        log_error("write() error: %s", strerror(errno));
        return -1;
    }
    n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;
    return 0;

}
int inter_fn_event_handle(struct nf_ctx *n_ctx)
{

    int ret;
    void *txn;
    ret = new_io_rx(n_ctx->nf_id, &txn);
    if (unlikely(ret == -1))
    {
        log_error("io_rx() error");
        return ret;
    }
    ret = write_to_worker(n_ctx, txn);

    if (unlikely(ret == -1))
    {
        log_error("write() error: %s", strerror(errno));
        return -1;
    }
    n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;
    return 0;
}


void recv_data(struct nf_ctx *n_ctx) {
    uint32_t data;
    int bytes_read = 0;
    // bytes_read = read_full(n_ctx->client_fd, &data, sizeof(uint32_t));
    bytes_read = recv(n_ctx->client_fd, &data, sizeof(data), 0);
    if (bytes_read <= 0) {
        perror("Failed to read length");
    }
    data = ntohl(data);
    log_debug("received %d", data);

    // // Convert from network byte order
    // json_len = ntohl(json_len);
    // std::cout << json_len << endl;
    //
    // memset(n_ctx->json_str, 0, 2048);
    // bytes_read = read_full(n_ctx->client_fd, n_ctx->json_str, json_len);
    // // bytes_read = recv(n_ctx->client_fd, n_ctx->json_str, json_len, 0);
    // if (bytes_read <= 0) {
    //     perror("Failed to read JSON string");
    //     close(n_ctx->client_fd);
    //     epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_DEL, n_ctx->client_fd, nullptr);
    //     return;
    // }
    // log_info("received json %s", n_ctx->json_str);
    //
    // // Parse and print the JSON
    // try {
    //     json received_json = json::parse(n_ctx->json_str);
    //     std::cout << "Received JSON: " << received_json.dump(4) << "\n";
    // } catch (json::parse_error& e) {
    //     std::cerr << "JSON parsing error: " << e.what() << "\n";
    // }
    //
}
static int ep_event_process(struct epoll_event &event, struct nf_ctx *n_ctx)
{
    int ret;
    uint64_t flag;
    struct fd_ctx_t *fd_tp = (struct fd_ctx_t *)event.data.ptr;
    struct epoll_event new_event;
    int bytes_read;
    if (fd_tp->fd_tp == INTER_FNC_SKT_FD) {
        ret = inter_fn_event_handle(n_ctx);
    }
    // send a packt
    if (fd_tp->fd_tp == EVENT_FD) {
        log_debug("receive event");
        bytes_read = read(n_ctx->tx_rx_pp[0], &flag, sizeof(uint64_t));
        if (bytes_read != sizeof(uint64_t)) {
            log_debug("read event fd error");
        }
        struct http_transaction *txn = nullptr;
        void *tmp = (void*)txn;
        generate_pkt(n_ctx, &tmp);
        ret = write_to_worker(n_ctx, tmp);
        if (unlikely(ret == -1)) {
            log_error("write to workder error");
        }

    }
    if (fd_tp->fd_tp == ING_FD) {

        log_debug("receive external client");
        n_ctx->client_fd = accept(n_ctx->ing_fd, NULL, NULL);

        struct http_transaction *txn = nullptr;
        void *tmp = (void*)txn;
        generate_pkt(n_ctx, &tmp);
        ret = write_to_worker(n_ctx, tmp);
        if (unlikely(ret == -1)) {
            log_error("write to workder error");
        }

        struct fd_ctx_t *clt_sk_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        clt_sk_ctx->sockfd      = n_ctx->client_fd;
        clt_sk_ctx->fd_tp = CLIENT_FD;
        n_ctx->fd_to_fd_ctx[n_ctx->client_fd] = clt_sk_ctx;

        new_event.events = EPOLLIN;
        new_event.data.ptr = clt_sk_ctx;
        ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->client_fd, &new_event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return -1;
        }
        log_debug("epoll added");
    }
    if (fd_tp->fd_tp == CLIENT_FD) {
        log_debug("client fd");
        recv_data(n_ctx);

    }
    if (fd_tp->fd_tp == COMCH_PE_FD) {
        doca_pe_clear_notification(n_ctx->comch_client_pe, 0);
        log_debug("dealing with comch fd");
        while (doca_pe_progress(n_ctx->comch_client_pe))
        {
        }

    }
    return 0;

}
void *basic_nf_rx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    uint8_t i;
    int ret;
    int n_event;
    struct epoll_event events[N_EVENTS_MAX];

    log_debug("self id is %u", n_ctx->nf_id);
    n_ctx->current_worker = 0;
    log_debug("Waiting for new RX events...");
    if (n_ctx->wait_point) {
        n_ctx->wait_point->count_down();
    }
    log_debug("rx not wait");
    while(true)
    {
        if (is_gtw_on_dpu(n_ctx->p_mode)) {
            doca_pe_request_notification(n_ctx->comch_client_pe);
        }
        n_event = epoll_wait(n_ctx->rx_ep_fd, events, N_EVENTS_MAX, -1);
        if (unlikely(n_event == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        log_debug("epoll_wait() returns %d new events", n_event);

        for (i = 0; i < n_event; i++)
        {
            ret = ep_event_process(events[i], n_ctx);
            RUNTIME_ERROR_ON_FAIL(ret == -1, "process event fail");

        }
    }
    return NULL;
}

// add epoll to get the events from pe and the skt
void *dpu_nf_rx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    uint8_t i;
    int ret;
    int n_event;
    struct epoll_event events[N_EVENTS_MAX];

    log_debug("self id is %u", n_ctx->nf_id);
    n_ctx->current_worker = 0;
    log_debug("Waiting for new RX events...");
    while(true)
    {
        n_event = epoll_wait(n_ctx->rx_ep_fd, events, N_EVENTS_MAX, -1);
        if (unlikely(n_event == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        log_debug("epoll_wait() returns %d new events", n_event);

        for (i = 0; i < n_event; i++)
        {
            ret = inter_fn_event_handle(n_ctx);
            RUNTIME_ERROR_ON_FAIL(ret == -1, "inter_fn_fail");
            n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;

        }
    }
    return NULL;

}
void nf_comch_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    // the user data is the ctx userdata
    struct nf_ctx *n_ctx = (struct nf_ctx *)user_data.ptr;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    doca_error_t result;
    struct doca_comch_task_send *task;
    struct comch_msg msg(0, 0, n_ctx->nf_id);
    int ret;
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC client context has been stopped");

        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        // need to get the connection object first
        DOCA_LOG_INFO("client context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("nf comch running");
        result = doca_comch_client_get_connection(n_ctx->comch_client, &n_ctx->comch_conn);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to get connection from client with error = %s", doca_error_get_name(result));
            throw runtime_error("fail to connect comch");
            (void)doca_ctx_stop(ctx);
        }

        // the ctx user_data is the n_ctx
        result = doca_comch_connection_set_user_data(n_ctx->comch_conn, user_data);
        LOG_AND_FAIL(result);

        // send the initial msg, next_fn = 0, the ptr = 0
        result =
            comch_client_send_msg(n_ctx->comch_client, n_ctx->comch_conn, (void*)&msg, sizeof(struct comch_msg), user_data, &task);
        LOG_AND_FAIL(result);
        DOCA_LOG_INFO("connection send");


        if (n_res.nf_mode == ACTIVE_SEND) {
            void *tmp = nullptr;
            generate_pkt(n_ctx, &tmp);
            if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->start) != 0)
            {
                DOCA_LOG_ERR("Failed to get timestamp");
            }
            ret = forward_or_end(n_ctx, (struct http_transaction*)tmp);
            if (unlikely(ret == -1)) {
                log_error("write to workder error");
            }

        }
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
void nf_message_recv_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer,
                                         uint32_t msg_len, struct doca_comch_connection *comch_connection)
{
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct nf_ctx *n_ctx = (struct nf_ctx *)user_data.u64;
    int ret;

    (void)event;

    uint64_t* u64p = reinterpret_cast<uint64_t*>(recv_buffer);
    uint64_t p = *u64p;
    log_debug("Message received: %d: %p: %lu", msg_len, recv_buffer, p);
    if (msg_len != sizeof(uint64_t)) {
        throw runtime_error("msg len error");
    }
    if (sizeof(uint64_t) != sizeof(struct http_transaction*))
    {
        throw runtime_error("ptr len error");

    }


    struct http_transaction *txn = reinterpret_cast<struct http_transaction*>(p);
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);
    ret = write_to_worker(n_ctx, txn);
    if (unlikely(ret == -1))
    {
        log_error("write() error: %s", strerror(errno));
        throw runtime_error("write pipe fail");
    }
}

void init_comch_client_cb(struct nf_ctx *n_ctx) {
    struct comch_cb_config &cb_cfg = n_ctx->comch_client_cb;
    cb_cfg.data_path_mode = false;
    cb_cfg.ctx_user_data = (void*)n_ctx;
    cb_cfg.send_task_comp_cb = basic_send_task_completion_callback;
    cb_cfg.send_task_comp_err_cb = basic_send_task_completion_err_callback;
    cb_cfg.msg_recv_cb = nf_message_recv_callback;
    cb_cfg.new_consumer_cb = nullptr;
    cb_cfg.expired_consumer_cb = nullptr;
    cb_cfg.ctx_state_changed_cb = nf_comch_state_changed_callback;
    cb_cfg.server_connection_event_cb = nullptr;
    cb_cfg.server_disconnection_event_cb = nullptr;


}

void rtc_nf_message_recv_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer,
                                         uint32_t msg_len, struct doca_comch_connection *comch_connection)
{
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct nf_ctx *n_ctx = (struct nf_ctx *)user_data.u64;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    int ret;

    (void)event;

    uint64_t* u64p = reinterpret_cast<uint64_t*>(recv_buffer);
    uint64_t p = *u64p;
    log_debug("Message received: %d: %p: %lu", msg_len, recv_buffer, p);
    if (msg_len != sizeof(uint64_t)) {
        throw runtime_error("msg len error");
    }
    if (sizeof(uint64_t) != sizeof(struct http_transaction*))
    {
        throw runtime_error("ptr len error");

    }


    struct http_transaction *txn = reinterpret_cast<struct http_transaction*>(p);
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);
    ret = forward_or_end(n_ctx, txn);
    if (unlikely(ret == -1))
    {
        log_error("write() error: %s", strerror(errno));
        throw runtime_error("write pipe fail");
    }
    if (n_res.nf_mode == ACTIVE_SEND) {
        if (n_ctx->received_pkg < n_ctx->expected_pkt) {
            log_debug("generate pkt");
            void *tmp = nullptr;
            generate_pkt(n_ctx, &tmp);
            ret = forward_or_end(n_ctx, (struct http_transaction*)tmp);
        }
        else {
            if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->end) != 0)
            {
                DOCA_LOG_ERR("Failed to get timestamp");
            }
            double tt_time = calculate_timediff_usec(&n_ctx->end, &n_ctx->start);
            double rps = n_ctx->expected_pkt / tt_time * USEC_PER_SEC;
            log_info("nf %d speed: %f usec", n_ctx->nf_id, tt_time / n_ctx->expected_pkt);
            log_info("nf rps: %f ", rps);
        }

    }
}

int forward_or_end(struct nf_ctx *n_ctx, struct http_transaction *txn)
{
    log_debug("forward or end");
    log_debug("txn addr %lu", reinterpret_cast<uint64_t>(txn));
    int ret = 0;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    uint32_t tenant_id = n_res.tenant_id;
    auto& t_res = n_ctx->tenant_id_to_res[tenant_id];
    struct doca_comch_task_send *task;
    union doca_data user_data;
    user_data.u64 = reinterpret_cast<uint64_t>(n_ctx);
    doca_error_t result;

    txn->hop_count++;
    log_debug("hop count %d", txn->hop_count);

    if (likely(txn->hop_count < cfg->route[txn->route_id].length))
    {
        txn->next_fn = cfg->route[txn->route_id].hop[txn->hop_count];
    }
    else
    {
        txn->next_fn = 0;
        if (n_res.nf_mode == ACTIVE_SEND) {
            log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u) finished!!!!",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);
            n_ctx->received_pkg++;
            log_debug("finish [%d] msg", n_ctx->received_pkg);

            rte_mempool_put(t_res.mp_ptr, txn);
            return 0;
        }
        // should not happen except the none sending nf
    }

    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);

    if (is_gtw_on_dpu(n_ctx->p_mode)) {
        uint32_t next_fn_node = n_ctx->fn_id_to_res[txn->next_fn].node_id;
        if (next_fn_node != n_ctx->node_id || txn->next_fn == 0) {
            log_debug("send ptr %lu", reinterpret_cast<uint64_t>(txn));
            struct comch_msg msg(reinterpret_cast<uint64_t>(txn), txn->next_fn, txn->ing_id);
            result = comch_client_send_msg_retry(n_ctx->comch_client, n_ctx->comch_conn, (void*)&msg, sizeof(struct comch_msg), user_data, &task);
            LOG_AND_FAIL(result);
            return 0;
        }
    }
    ret = new_io_tx(n_ctx->nf_id, txn, txn->next_fn);
    if (unlikely(ret == -1))
    {
        log_error("io_tx() error");
        return 0;
    }
}
int rtc_inter_fn_event_handle(struct nf_ctx *n_ctx)
{

    int ret;
    void *txn;
    ret = new_io_rx(n_ctx->nf_id, &txn);
    if (unlikely(ret == -1))
    {
        log_error("io_rx() error");
        return ret;
    }
    ret = forward_or_end(n_ctx, (struct http_transaction*)txn);

    if (unlikely(ret == -1))
    {
        log_error("write() error: %s", strerror(errno));
        return -1;
    }
    n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;
    return 0;
}
int rtc_event_process(struct epoll_event& event, struct nf_ctx* n_ctx)
{
    int ret;
    struct fd_ctx_t *fd_tp = (struct fd_ctx_t *)event.data.ptr;
    if (fd_tp->fd_tp == INTER_FNC_SKT_FD) {
        ret = rtc_inter_fn_event_handle(n_ctx);
    }
    if (fd_tp->fd_tp == COMCH_PE_FD) {
        doca_pe_clear_notification(n_ctx->comch_client_pe, 0);
        log_debug("dealing with comch fd");
        while (doca_pe_progress(n_ctx->comch_client_pe))
        {
        }

    } else {
        log_error("unknown req type");
        return -1;
    }
    return 0;

}
void *run_tenant_expt(struct nf_ctx *n_ctx)
{
    uint8_t i;
    int ret;
    int n_event;
    struct epoll_event events[N_EVENTS_MAX];

    log_debug("self id is %u", n_ctx->nf_id);
    n_ctx->current_worker = 0;
    log_debug("Waiting for new RX events...");
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    // if (n_res.nf_mode == ACTIVE_SEND) {
    //     void *tmp = nullptr;
    //     generate_pkt(n_ctx, &tmp);
    //     if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->start) != 0)
    //     {
    //         DOCA_LOG_ERR("Failed to get timestamp");
    //     }
    //     ret = forward_or_end(n_ctx, (struct http_transaction*)tmp);
    //     if (unlikely(ret == -1)) {
    //         log_error("write to workder error");
    //     }
    //
    // }
    // while(true)
    // {
    //     if (is_gtw_on_dpu(n_ctx->p_mode)) {
    //         doca_pe_request_notification(n_ctx->comch_client_pe);
    //     }
    //     n_event = epoll_wait(n_ctx->rx_ep_fd, events, N_EVENTS_MAX, -1);
    //     if (unlikely(n_event == -1))
    //     {
    //         log_error("epoll_wait() error: %s", strerror(errno));
    //         return NULL;
    //     }
    //
    //     log_debug("epoll_wait() returns %d new events", n_event);
    //
    //     for (i = 0; i < n_event; i++)
    //     {
    //         ret = rtc_event_process(events[i], n_ctx);
    //         RUNTIME_ERROR_ON_FAIL(ret == -1, "process event fail");
    //
    //     }
    // }
    while(true) {
        doca_pe_progress(n_ctx->comch_client_pe);
        std::this_thread::sleep_for(std::chrono::microseconds(n_ctx->expt_setting.sleep_time));
    }
    return NULL;
}

void bf_pkt_send_task_completion_callback(struct doca_comch_task_send *task, union doca_data task_user_data,
                                         union doca_data ctx_user_data)
{

    (void)ctx_user_data;
    doca_task_free(doca_comch_task_send_as_task(task));
    /* This argument is not in use */
    struct nf_ctx *n_ctx = (struct nf_ctx*)ctx_user_data.u64;
    // DOCA_LOG_INFO("comp callback");
    int ret = 0;
    void *tmp = nullptr;
    generate_pkt(n_ctx, &tmp);
    ret = forward_or_end(n_ctx, (struct http_transaction*)tmp);

}

void rtc_init_comch_client_cb(struct nf_ctx *n_ctx) {
    struct comch_cb_config &cb_cfg = n_ctx->comch_client_cb;
    cb_cfg.data_path_mode = false;
    cb_cfg.ctx_user_data = (void*)n_ctx;
    cb_cfg.send_task_comp_cb = basic_send_task_completion_callback;
    cb_cfg.send_task_comp_err_cb = basic_send_task_completion_err_callback;
    cb_cfg.msg_recv_cb = rtc_nf_message_recv_callback;
    cb_cfg.new_consumer_cb = nullptr;
    cb_cfg.expired_consumer_cb = nullptr;
    cb_cfg.ctx_state_changed_cb = nf_comch_state_changed_callback;
    cb_cfg.server_connection_event_cb = nullptr;
    cb_cfg.server_disconnection_event_cb = nullptr;


}

void bf_pkt_comch_client_cb(struct nf_ctx *n_ctx) {
    struct comch_cb_config &cb_cfg = n_ctx->comch_client_cb;
    cb_cfg.data_path_mode = false;
    cb_cfg.ctx_user_data = (void*)n_ctx;
    cb_cfg.send_task_comp_cb = bf_pkt_send_task_completion_callback;
    cb_cfg.send_task_comp_err_cb = basic_send_task_completion_err_callback;
    cb_cfg.msg_recv_cb = rtc_nf_message_recv_callback;
    cb_cfg.new_consumer_cb = nullptr;
    cb_cfg.expired_consumer_cb = nullptr;
    cb_cfg.ctx_state_changed_cb = nf_comch_state_changed_callback;
    cb_cfg.server_connection_event_cb = nullptr;
    cb_cfg.server_disconnection_event_cb = nullptr;


}



int nf(uint32_t nf_id, struct nf_ctx *n_ctx, void *(*nf_worker) (void *))
{
    int level = log_get_level();

#ifdef DEBUG
    log_info("debug mode!!!");
    log_set_level(1);
    level = 1;
    
#endif
    enum my_log_level lv = static_cast<enum my_log_level>(level);

    doca_error_t result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, my_log_level_to_doca_log_level(lv));
    const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint32_t tenant_id;
    uint8_t i;
    int ret;
    struct epoll_event event;

    // fn_id = nf_id;

    memzone = rte_memzone_lookup(MEMZONE_NAME);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_lookup() error");
        return -1;
    }


    cfg = (struct spright_cfg_s *)memzone->addr;

    struct nf_ctx real_nf_ctx(cfg, nf_id);

    real_nf_ctx.print_nf_ctx();
    real_nf_ctx.print_gateway_ctx();



    n_ctx = &real_nf_ctx;

    ret = new_io_init(nf_id, &n_ctx->inter_fn_skt);
    if (unlikely(ret == -1))
    {
        log_error("io_init() error");
        return -1;
    }
    if (n_ctx->inter_fn_skt < 0) {
        throw std::runtime_error("skt error");
    }
    log_debug("the inter nf skt is %d", n_ctx->inter_fn_skt);

    tenant_id = n_ctx->fn_id_to_res[n_ctx->nf_id].tenant_id;
    auto& routes = n_ctx->tenant_id_to_res[tenant_id].routes;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    auto& t_res = n_ctx->tenant_id_to_res[tenant_id];
    std::string mp_name = mempool_prefix + std::to_string(tenant_id);

    if (n_ctx->p_mode != SPRIGHT) {
        t_res.mp_ptr = rte_mempool_lookup(mp_name.c_str());
        if (!t_res.mp_ptr) {
            throw std::runtime_error("palladium mempool didn't found");

        }

    }


    for (auto i: routes) {
        if (!n_ctx->route_id_to_res[i].hop.empty()) {
            if (n_ctx->route_id_to_res[i].hop[0] == n_ctx->nf_id) {
                n_ctx->routes_start_from_nf.push_back(i);
            }

        }
    }
    // if (n_res.nf_mode == ACTIVE_SEND && n_ctx->routes_start_from_nf.empty()) {
    //     throw std::runtime_error("no avaliable_routes");
    // }

    real_nf_ctx.print_nf_ctx();

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pipe(real_nf_ctx.pipefd_rx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }

        ret = pipe(real_nf_ctx.pipefd_tx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
    }

    n_ctx->rx_ep_fd = epoll_create1(0);
    if (unlikely(n_ctx->rx_ep_fd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
    }
    // create a ckt to listen to external client
    //
    n_ctx->ing_fd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, n_ctx->ing_port);
    if (unlikely(n_ctx->ing_fd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }
    struct fd_ctx_t *cmd_ckt_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    cmd_ckt_ctx->sockfd = n_ctx->ing_fd;
    cmd_ckt_ctx->fd_tp = ING_FD;

    n_ctx->fd_to_fd_ctx[n_ctx->ing_fd] = cmd_ckt_ctx;
    struct epoll_event ing_event;
    ing_event.events = EPOLLIN;
    ing_event.data.ptr = reinterpret_cast<void*>(cmd_ckt_ctx);

    ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->ing_fd, &ing_event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    if (n_res.nf_mode == ACTIVE_SEND) {
        struct epoll_event pp_event;
        ret = pipe(n_ctx->tx_rx_pp);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
        ret = set_nonblocking(n_ctx->tx_rx_pp[0]);
        if (unlikely(ret == -1))
        {
            log_error("set set_nonblocking error");
        }

        struct fd_ctx_t *tx_rx_pp_fd = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        tx_rx_pp_fd->fd_tp = EVENT_FD;
        tx_rx_pp_fd->sockfd = n_ctx->tx_rx_pp[0];

        // n_ctx->fd_to_fd_ctx[n_ctx->tx_rx_event_fd] = tx_rx_pp_fd;

        pp_event.data.ptr = reinterpret_cast<void*>(tx_rx_pp_fd);
        pp_event.events = EPOLLIN;

        ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->tx_rx_pp[0], &pp_event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            throw std::runtime_error("add ep pp");
        }
        log_debug("event fd added");
    }



    ret = set_nonblocking(n_ctx->inter_fn_skt);
    RUNTIME_ERROR_ON_FAIL(ret == -1, "set_nonblocking fail");


    struct fd_ctx_t *inter_fn_skt_fd = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    inter_fn_skt_fd->fd_tp = INTER_FNC_SKT_FD;
    inter_fn_skt_fd->sockfd = n_ctx->inter_fn_skt;

    event.events = EPOLLIN;
    event.data.ptr = reinterpret_cast<void*>(inter_fn_skt_fd);

    ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->inter_fn_skt, &event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }
    if (is_gtw_on_dpu(n_ctx->p_mode)) {
        log_info("dpu mode");

        if (cfg->tenant_expt == 1) {

            if (n_ctx->expt_setting.bf_mode) {
                bf_pkt_comch_client_cb(n_ctx);

            }
            else {
                rtc_init_comch_client_cb(n_ctx);

            }
        }
        else {
            init_comch_client_cb(n_ctx);

        }

        result = open_doca_device_with_pci(n_ctx->comch_client_device_name.c_str(), NULL, &(n_ctx->comch_client_dev));
        LOG_AND_FAIL(result);

        result =
            init_comch_client(comch_server_name.c_str(), n_ctx->comch_client_dev, &n_ctx->comch_client_cb, &(n_ctx->comch_client), &(n_ctx->comch_client_pe), &(n_ctx->comch_client_ctx));
        LOG_AND_FAIL(result);

        struct fd_ctx_t *comch_pe_fd_tp = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        comch_pe_fd_tp->fd_tp = COMCH_PE_FD;
        result = register_pe_to_ep_with_fd_tp(n_ctx->comch_client_pe, n_ctx->rx_ep_fd, comch_pe_fd_tp, n_ctx);
        LOG_AND_FAIL(result);

    }
    n_ctx->wait_point.emplace(1);


    if (cfg->tenant_expt == 1) {
        log_debug("run tenant expt");
        run_tenant_expt(n_ctx);
        return 0;
    }

    ret = pthread_create(&thread_rx, NULL, &basic_nf_rx, n_ctx);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_create(&thread_tx, NULL, &basic_nf_tx, n_ctx);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }


    ret = pthread_join(thread_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(thread_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = close(real_nf_ctx.pipefd_rx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_rx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_tx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = new_io_exit(n_ctx->nf_id);
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}
