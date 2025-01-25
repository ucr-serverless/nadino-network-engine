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
#include <stdexcept>
#include <sys/epoll.h>

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

    std::cout << "routes_start_from_nf: ";
    for (const auto& route : routes_start_from_nf) {
        std::cout << route << " ";
    }
    std::cout << "\n";

    cout<< "nf_id: " << this->nf_id << endl;

}



void generate_pkt(struct nf_ctx *n_ctx, void** txn)
{
    int ret = 0;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    if (unlikely(ret < 0))
    {
        log_error("rte_mempool_get() error: %s", g_strerror(-ret));
    }
    uint32_t tenant_id = n_res.tenant_id;
    auto &t_res = n_ctx->tenant_id_to_res[tenant_id];
    ret = rte_mempool_get(t_res.mp_ptr, (void **)&txn);
    struct http_transaction *pkt = (struct http_transaction*)*txn;
    pkt->tenant_id = tenant_id;
    pkt->route_id = n_ctx->routes_start_from_nf[0];
    // skip the initial processing of the first function
    pkt->hop_count = 0;
    // thr route should not be only only one function
    pkt->next_fn = n_ctx->nf_id;
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
    uint8_t flag_to_send;

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

    if (n_res.nf_mode == ACTIVE_SEND) {

        // send the initial signal to create pkt
        int write_bytes = write(n_ctx->tx_rx_event_fd, &flag_to_send, sizeof(uint8_t));
        if (unlikely(write_bytes == -1)) {
            log_error("write to rx");
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
                    // return elements
                    write(n_ctx->tx_rx_event_fd, &flag_to_send, sizeof(uint8_t));
                    rte_mempool_put(t_res.mp_ptr, txn);
                    continue;
                    // TODO: create a new pkt and send out
                }
            }

            log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
                      txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
                      txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            if (is_gtw_on_dpu(n_ctx->p_mode)) {
                uint32_t next_fn_node = n_ctx->fn_id_to_res[txn->next_fn].node_id;
                if (next_fn_node != n_ctx->node_id || txn->next_fn == 0) {
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

static int ep_event_process(struct epoll_event &event, struct nf_ctx *n_ctx)
{
    int ret;
    uint8_t flag;
    struct fd_ctx_t *fd_tp = (struct fd_ctx_t *)event.data.ptr;
    if (fd_tp->fd_tp == INTER_FNC_SKT_FD) {
        ret = inter_fn_event_handle(n_ctx);
    }
    // send a packt
    if (fd_tp->fd_tp == EVENT_FD) {
        read(fd_tp->sockfd, &flag, sizeof(uint8_t));
        struct http_transaction *txn = nullptr;
        void *tmp = (void*)txn;
        generate_pkt(n_ctx, &tmp);
        ret = write_to_worker(n_ctx, tmp);
        if (unlikely(ret == -1)) {
            log_error("write to workder error");
        }

    }
    if (fd_tp->fd_tp == COMCH_PE_FD) {
        doca_pe_clear_notification(n_ctx->comch_client_pe, 0);
        log_info("dealing with rdma fd");
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
            ret = ep_event_process(events[i], n_ctx);
            RUNTIME_ERROR_ON_FAIL(ret == -1, "inter_fn_fail");
            n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;

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

    log_debug("Message received: '%.*s'", (int)msg_len, recv_buffer);
    if (msg_len != sizeof(uint64_t)) {
        throw runtime_error("msg len error");
    }
    if (sizeof(uint64_t) != sizeof(struct http_transaction*))
    {
        throw runtime_error("ptr len error");

    }
    ret = write_to_worker(n_ctx, (void*)recv_buffer);
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
