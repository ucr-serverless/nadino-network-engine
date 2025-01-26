#include "palladium_nf_common.h"
#include "comch_ctrl_path_common.h"
#include "common_doca.h"
#include "http.h"
#include "io.h"
#include "log.h"
#include "palladium_doca_common.h"
#include "rte_branch_prediction.h"
#include "spright.h"
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/epoll.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

DOCA_LOG_REGISTER(PALLADIUM_NF::COMMON);
using namespace std;
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

}



void generate_pkt(struct nf_ctx *n_ctx, void** txn)
{
    log_debug("generate pkt");
    int ret = 0;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    uint32_t tenant_id = n_res.tenant_id;
    auto &t_res = n_ctx->tenant_id_to_res[tenant_id];

    ret = rte_mempool_get(t_res.mp_ptr, txn);
    if (unlikely(ret < 0))
    {
        log_error("rte_mempool_get() error: %s", g_strerror(-ret));
    }

    RUNTIME_ERROR_ON_FAIL(ret != 0, "get element fail");
    uint64_t p = reinterpret_cast<uint64_t>(txn);
    log_debug("the txn addr: %p, %d", txn, p);
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

        // send the initial signal to create pkt
        int bytes_written = write(n_ctx->tx_rx_pp[1], &flag_to_send, sizeof(uint64_t));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
        }
        log_info("send first packet");
        
        if (clock_gettime(CLOCK_TYPE_ID, &n_ctx->start) != 0)
        {
            DOCA_LOG_ERR("Failed to get timestamp");
        }

    }
    
    while (1)
    {
        n_fds = epoll_wait(epfd, event, cfg->nf[n_ctx->nf_id - 1].n_threads, -1);
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

                    if (txn->nf_get == 1) {
                        log_debug("nf get it");
                        rte_mempool_put(t_res.mp_ptr, txn);

                    }
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
                    result = comch_client_send_msg(n_ctx->comch_client, n_ctx->comch_conn, (void*)&msg, sizeof(struct comch_msg), user_data, &task);
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
    doca_error_t result;
    struct doca_comch_task_send *task;
    struct comch_msg msg(0, 0, n_ctx->nf_id);
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
