#include "palladium_nf_common.h"
#include "comch_ctrl_path_common.h"
#include "palladium_doca_common.h"
#include <stdexcept>

DOCA_LOG_REGISTER(PALLADIUM_NF::COMMON);
using namespace std;

void nf_ctx::print_nf_ctx() {
    gateway_ctx::print_gateway_ctx();

    cout << endl;
    cout<< "nf_id: " << this->nf_id << endl;

}
void *basic_nf_tx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    struct http_transaction *txn = NULL;
    ssize_t bytes_read;
    uint8_t i;
    int n_fds;
    int epfd;
    int ret;

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
            }

            log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()",
                      txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
                      txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            // TODO: add branch to jump to inter node or intra node(if use RDMA)
            // RDMA and socket will use different message(skt pass pointer), RDMA pass ptr+next_fn
            // A map of fn_id to node id is needed
            // check whether the fn is local and if it is call the 
            ret = io_tx(txn, txn->next_fn);
            if (unlikely(ret == -1))
            {
                log_error("io_tx() error");
                return NULL;
            }
        }
    }

    return NULL;
}

void *basic_nf_rx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    uint8_t i;
    int ret;
    log_debug("self id is %u", n_ctx->nf_id);

    for (i = 0;; i = (i + 1) % cfg->nf[n_ctx->nf_id - 1].n_threads)
    {
        // TODO: receive from the comch to get new requests
        ret = io_rx((void **)&txn);
        if (unlikely(ret == -1))
        {
            log_error("io_rx() error");
            return NULL;
        }

        bytes_written = write(n_ctx->pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

void *dpu_nf_rx(void *arg)
{
    struct nf_ctx *n_ctx = (struct nf_ctx*)arg;
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    uint8_t i;
    int ret;
    log_debug("self id is %u", n_ctx->nf_id);

    for (i = 0;; i = (i + 1) % cfg->nf[n_ctx->nf_id - 1].n_threads)
    {
        // TODO: receive from the comch to get new requests
        ret = io_rx((void **)&txn);
        if (unlikely(ret == -1))
        {
            log_error("io_rx() error");
            return NULL;
        }

        bytes_written = write(n_ctx->pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
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
        result = doca_comch_client_get_connection(n_ctx->comch_client, &n_ctx->comch_conn);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to get connection from client with error = %s", doca_error_get_name(result));
            throw runtime_error("fail to connect comch");
            (void)doca_ctx_stop(ctx);
        }

        result = doca_comch_connection_set_user_data(n_ctx->comch_conn, user_data);
        LOG_AND_FAIL(result);

        result =
            comch_client_send_msg(n_ctx->comch_client, n_ctx->comch_conn, (void*)&msg, sizeof(struct comch_msg), user_data, &task);
        LOG_AND_FAIL(result);

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
    struct nf_ctx *n_ctx = (struct nf_ctx *)user_data.ptr;
    int bytes_written;

    (void)event;

    log_debug("Message received: '%.*s'", (int)msg_len, recv_buffer);
    bytes_written = write(n_ctx->pipefd_rx[n_ctx->current_worker][1], &recv_buffer, sizeof(uint64_t));
    if (unlikely(bytes_written == -1))
    {
        log_error("write() error: %s", strerror(errno));
        throw runtime_error("write pipe fail");
    }

    n_ctx->current_worker = (n_ctx->current_worker + 1) % n_ctx->n_worker;
}
