/*gate
# Copyright 2025 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <errno.h>
#include <memory>
#include <netinet/tcp.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_memzone.h>

#include "common_doca.h"
#include "doca_error.h"
#include "doca_pe.h"
#include "glib.h"
#include "http.h"
#include "io.h"
#include "log.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"
#include "spright.h"
#include "timer.h"
#include "utility.h"
#include <unordered_map>
#include <utility>
#include "palladium_doca_common.h"

DOCA_LOG_REGISTER(PALLADIUM_GATEWAY::MAIN);
#define IS_SERVER_TRUE 1
#define IS_SERVER_FALSE 0
#define NUM_LCORES 4

#define HTTP_RESPONSE                                                                                                  \
    "HTTP/1.1 200 OK\r\n"                                                                                              \
    "Connection: close\r\n"                                                                                            \
    "Content-Type: text/plain\r\n"                                                                                     \
    "Content-Length: 13\r\n"                                                                                           \
    "\r\n"                                                                                                             \
    "Hello World\r\n"

struct server_vars
{
    int rpc_svr_sockfd; // Handle intra-cluster RPCs
    int ing_svr_sockfd; // Handle external clients
    int epfd;
};


int peer_node_sockfds[ROUTING_TABLE_SIZE];

struct gateway_ctx *g_ctx;


static int dispatch_msg_to_fn(struct http_transaction *txn)
{
    int ret;

    if (txn->next_fn != cfg->route[txn->route_id].hop[txn->hop_count])
    {
        if (txn->hop_count == 0)
        {
            txn->next_fn = cfg->route[txn->route_id].hop[txn->hop_count];
            log_debug("Dispatcher receives a request from conn_read.");
        }
        else
        {
            log_debug("Dispatcher receives a request from conn_write or rpc_server.");
        }
    }

    ret = io_tx(txn, txn->next_fn);
    if (unlikely(ret == -1))
    {
        log_error("io_tx() error");
        return -1;
    }

    return 0;
}

static int rpc_client_setup(char *server_ip, uint16_t server_port, uint8_t peer_node_idx)
{
    log_info("RPC client connects with node %u (%s:%u).", peer_node_idx, cfg->nodes[peer_node_idx].ip_address,
             g_ctx->rpc_svr_port);

    struct sockaddr_in server_addr;
    int sockfd;
    int ret;
    int opt = 1;

    log_debug("Destination Gateway Address (%s:%u).", server_ip, server_port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    // Set SO_REUSEADDR to reuse the address
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(sockfd);
        return -1;
    }

    configure_keepalive(sockfd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    ret = retry_connect(sockfd, (struct sockaddr *)&server_addr);
    if (unlikely(ret == -1))
    {
        log_error("connect() failed: %s", strerror(errno));
        return -1;
    }

    return sockfd;
}

static int rpc_client_send(int peer_node_idx, struct http_transaction *txn)
{
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, \
        Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);

    ssize_t bytes_sent;
    int sockfd = peer_node_sockfds[peer_node_idx];

    bytes_sent = send(sockfd, txn, sizeof(*txn), 0);

    log_debug("sockfd: %d, peer_node_idx: %d \t bytes_sent: %ld \t sizeof(*txn): %ld", sockfd, peer_node_idx, bytes_sent, sizeof(*txn));
    if (unlikely(bytes_sent == -1))
    {
        log_error("send() error: %s", strerror(errno));
        return -1;
    }

    log_debug("rpc_client_send is done.");

    return 0;
}

// static int rpc_client_close(int peer_node_idx) {

// 	int sockfd = peer_node_sockfds[peer_node_idx];

// 	ret = close(sockfd);
// 	if (unlikely(ret == -1)) {
// 		log_error("close() error: %s", strerror(errno));
// 		return -1;
// 	}

// peer_node_sockfds[peer_node_idx] = 0;

// 	return 0;
// }

int rpc_client(struct http_transaction *txn)
{
    int ret;

    uint8_t peer_node_idx = g_ctx->fn_id_to_res[txn->next_fn].node_id;
    log_debug("the node_id for fn_id %d is %d", peer_node_idx, txn->next_fn);
    if (peer_node_sockfds[peer_node_idx] == 0)
    {
        peer_node_sockfds[peer_node_idx] =
            rpc_client_setup(cfg->nodes[peer_node_idx].ip_address, g_ctx->rpc_svr_port, peer_node_idx);
    }
    else if (peer_node_sockfds[peer_node_idx] < 0)
    {
        log_error("Invalid socket error.");
        return -1;
    }

    ret = rpc_client_send(peer_node_idx, txn);
    if (unlikely(ret == -1))
    {
        log_error("rpc_client_send() failed: %s", strerror(errno));
        return -1;
    }

    rte_mempool_put(cfg->mempool, txn);

    return 0;
}

static int conn_accept(int svr_sockfd, struct server_vars *sv)
{
    struct epoll_event event;
    int clt_sockfd;
    int ret;
    struct fd_ctx_t *clt_sk_ctx = NULL;
    clt_sockfd = accept(svr_sockfd, NULL, NULL);
    if (unlikely(clt_sockfd == -1))
    {
        log_error("accept() error: %s", strerror(errno));
        goto error_0;
    }

    log_debug("connection accepted %d !!!!", clt_sockfd);

    clt_sk_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    clt_sk_ctx->sockfd      = clt_sockfd;
    clt_sk_ctx->is_server   = IS_SERVER_FALSE;
    clt_sk_ctx->peer_svr_fd = svr_sockfd;
    clt_sk_ctx->fd_tp = CLIENT_FD;
    g_ctx->fd_to_fd_ctx[clt_sockfd] = clt_sk_ctx;

    /* Configure RPC connection keepalive 
     * TODO: keep external connection alive 
     */
    if (svr_sockfd == sv->rpc_svr_sockfd)
    {
        log_debug("Set RPC connection to keep alive.");
        configure_keepalive(clt_sockfd);
        event.events = EPOLLIN;
    } else // svr_sockfd == sv->ing_svr_sockfd
    {
        event.events = EPOLLIN | EPOLLONESHOT;
    }

    event.data.ptr = clt_sk_ctx;

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, clt_sockfd, &event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    close(clt_sockfd);
    free(clt_sk_ctx);
error_0:
    return -1;
}

static int conn_close(struct server_vars *sv, int sockfd)
{
    int ret;

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sockfd, NULL);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        goto error_1;
    }

    ret = close(sockfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        goto error_0;
    }

    return 0;

error_1:
    close(sockfd);
error_0:
    return -1;
}

static void parse_route_id(struct http_transaction *txn)
{
    const char *string = strstr(txn->request, "/");
    if (unlikely(string == NULL)) {
        txn->route_id = 0;
    } else {
        // Skip consecutive slashes in one step
        string += strspn(string, "/");
        errno = 0;
        txn->route_id = strtol(string, NULL, 10);
        if (unlikely(errno != 0 || txn->route_id < 0)) {
            txn->route_id = 0;
        }
    }
    log_debug("Route ID: %d", txn->route_id);
}
// read for naive ing
static int conn_read(int sockfd, void* sk_ctx)
{
    log_debug("read data from client");
    struct http_transaction *txn = NULL;
    struct http_transaction tmp_txn;
    struct http_transaction *multi_tenant_txn = nullptr;
    struct rte_mempool *mp = nullptr;
    int read_cnt = 0;
    int ret;

    if (g_ctx->p_mode == SPRIGHT) {
        ret = rte_mempool_get(cfg->mempool, (void **)&txn);
        if (unlikely(ret < 0))
        {
            log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
            goto error_0;
        }
    }
    // conn_write is only used in spright mode and palladium on host modes
    else if (g_ctx->tenant_id_to_res.size() == 1) {
        // single tenant in palladium same node mode
        ret = rte_mempool_get(g_ctx->tenant_id_to_res[0].mp_ptr, (void **)&txn);
        if (unlikely(ret < 0))
        {
            log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
            goto error_0;
        }
    } else {
        // first receive then parse route then 
        // copy to correct mp in palladium multi tenancy case
        txn = &tmp_txn;

    }


    // txn->is_rdma_remote_mem = 0;

    log_debug("Receiving from External User.");
    read_cnt = read(sockfd, txn->request, HTTP_MSG_LENGTH_MAX);
    if (unlikely(read_cnt < 0))
    {
        log_error("read() error: %s", strerror(errno));
        goto error_1;
    }
    txn->length_request = read_cnt;

    txn->sockfd = sockfd;
    txn->sk_ctx = sk_ctx;

    if (g_ctx->p_mode == SPRIGHT) {
        txn->tenant_id = 0;
    }


    parse_route_id(txn);

    // the default route
    // if multiple tenant exits, just assign it to the tenant with lowest tenant_id
    if(!g_ctx->route_id_to_res.count(txn->route_id)) {
        log_fatal("route id error");
        goto error_1;
    } else {
        txn->tenant_id = g_ctx->route_id_to_res[txn->route_id].tenant_id;
    }

    if (g_ctx->p_mode != SPRIGHT && g_ctx->tenant_id_to_res.size() > 1) {
        // use rdma mode, copy is a work around to test multi tenancy on same node
        // the true test should use the nf to init the req
        mp = g_ctx->tenant_id_to_res[txn->tenant_id].mp_ptr;
        ret = rte_mempool_get(mp, (void **)&multi_tenant_txn);
        if (unlikely(ret < 0))
        {
            log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
            goto error_0;
        }
        memcpy(multi_tenant_txn, txn, sizeof(struct http_transaction));
        // reuse the pointer
        txn = multi_tenant_txn;
        
    }

    // TODO: take care of this
    txn->hop_count = 0;

    ret = dispatch_msg_to_fn(txn);
    if (unlikely(ret == -1))
    {
        log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    rte_mempool_put(cfg->mempool, txn);
error_0:
    return -1;
}

// spright Inter-node receive
static int rpc_server_receive(int sockfd)
{
    int ret;
    struct http_transaction *txn = NULL;
    ssize_t total_bytes_received = 0;

    ret = rte_mempool_get(cfg->mempool, (void **)&txn);
    if (unlikely(ret < 0))
    {
        log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
        goto error_0;
    }

    log_debug("Receiving message from remote gateway.");
    total_bytes_received = read_full(sockfd, txn, sizeof(*txn));
    if (total_bytes_received == -1)
    {
        log_error("read_full() error");
        goto error_1;
    }
    else if (total_bytes_received != sizeof(*txn))
    {
        log_error("Incomplete transaction received: expected %ld, got %zd", sizeof(*txn), total_bytes_received);
        goto error_1;
    }

    log_debug("Bytes received: %zd. \t sizeof(*txn): %ld.", total_bytes_received, sizeof(*txn));

    // Send txn to local function
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

    ret = dispatch_msg_to_fn(txn);
    if (unlikely(ret == -1))
    {
        log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    rte_mempool_put(cfg->mempool, txn);
    close(sockfd);
error_0:
    return -1;
}

// use rdma to write to others
static int rdma_write(int *sockfd, struct server_vars* sv)

{
    struct http_transaction *txn = NULL;
    ssize_t bytes_sent;
    int ret;
    struct rte_mempool *mp = nullptr;

    log_debug("Waiting for the next TX event.");

    ret = io_rx((void **)&txn);
    if (unlikely(ret == -1))
    {
        log_error("io_rx() error");
        goto error_0;
    }

    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

    // Inter-node Communication (use rpc_client method)
    if (cfg->route[txn->route_id].hop[txn->hop_count] != g_ctx->gtw_fn_id)
    {
        ret = rdma_send(txn, g_ctx, txn->tenant_id);
        if (unlikely(ret == -1))
        {
            goto error_1;
        }

        // free buffer in the send imme callback
        goto keep_connection;
    }

    txn->hop_count++;
    log_debug("Next hop is Fn %u", cfg->route[txn->route_id].hop[txn->hop_count]);
    txn->next_fn = cfg->route[txn->route_id].hop[txn->hop_count];

    // Intra-node Communication (use io_tx() method)
    if (txn->hop_count < cfg->route[txn->route_id].length)
    {
        ret = dispatch_msg_to_fn(txn);
        if (unlikely(ret == -1))
        {
            log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
            goto error_1;
        }

        goto keep_connection;
    }

    // Respond External Client
    *sockfd = txn->sockfd;

    txn->length_response = strlen(HTTP_RESPONSE);
    memcpy(txn->response, HTTP_RESPONSE, txn->length_response);

    /* TODO: Handle incomplete writes */
    // return to external client
    bytes_sent = write(*sockfd, txn->response, txn->length_response);
    if (unlikely(bytes_sent == -1))
    {
        log_error("write() error: %s", strerror(errno));
        goto error_1;
    }

    // if (txn->is_rdma_remote_mem == 1)
    // {
    //     struct control_server_msg msg = {
    //         .source_node_idx = cfg->local_node_idx,
    //         .dest_node_idx = txn->rdma_send_node_idx,
    //         .source_qp_num = txn->rdma_recv_qp_num,
    //         .slot_idx = txn->rdma_slot_idx,
    //         .n_slot = txn->rdma_n_slot,
    //         .bf_addr = txn,
    //         .bf_len = sizeof(struct http_transaction),
    //
    //     };
    //     // send_release_signal(&msg);
    // }
    // else
    {
        free(txn->sk_ctx);
        // fix segfault of multi tenancy
        mp = g_ctx->tenant_id_to_res[txn->tenant_id].mp_ptr;
        rte_mempool_put(mp, txn);
        log_debug("Closing the connection after TX.\n");
        ret = conn_close(sv, *sockfd);
        if (unlikely(ret == -1))
        {
            log_error("conn_close() error");
            return -1;
        }
        return ret;
    }

keep_connection:
    return 0;

error_1:
    free(txn->sk_ctx);
    rte_mempool_put(mp, txn);
error_0:
    return -1;
}
static int conn_write(int *sockfd)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_sent;
    int ret;

    log_debug("Waiting for the next TX event.");

    ret = io_rx((void **)&txn);
    if (unlikely(ret == -1))
    {
        log_error("io_rx() error");
        goto error_0;
    }

    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

    // Inter-node Communication (use rpc_client method)
    if (cfg->route[txn->route_id].hop[txn->hop_count] != g_ctx->gtw_fn_id)
    {
        ret = rpc_client(txn);
        if (unlikely(ret == -1))
        {
            goto error_1;
        }

        return 1;
    }

    txn->hop_count++;
    log_debug("Next hop is Fn %u", cfg->route[txn->route_id].hop[txn->hop_count]);
    txn->next_fn = cfg->route[txn->route_id].hop[txn->hop_count];

    // Intra-node Communication (use io_tx() method)
    if (txn->hop_count < cfg->route[txn->route_id].length)
    {
        ret = dispatch_msg_to_fn(txn);
        if (unlikely(ret == -1))
        {
            log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
            goto error_1;
        }

        return 1;
    }

    // Respond External Client
    *sockfd = txn->sockfd;

    txn->length_response = strlen(HTTP_RESPONSE);
    memcpy(txn->response, HTTP_RESPONSE, txn->length_response);

    /* TODO: Handle incomplete writes */
    bytes_sent = write(*sockfd, txn->response, txn->length_response);
    if (unlikely(bytes_sent == -1))
    {
        log_error("write() error: %s", strerror(errno));
        goto error_1;
    }

    // if (txn->is_rdma_remote_mem == 1)
    // {
    //     struct control_server_msg msg = {
    //         .source_node_idx = cfg->local_node_idx,
    //         .dest_node_idx = txn->rdma_send_node_idx,
    //         .source_qp_num = txn->rdma_recv_qp_num,
    //         .slot_idx = txn->rdma_slot_idx,
    //         .n_slot = txn->rdma_n_slot,
    //         .bf_addr = txn,
    //         .bf_len = sizeof(struct http_transaction),
    //
    //     };
    //     // send_release_signal(&msg);
    // }
    // else
    {
        free(txn->sk_ctx);
        rte_mempool_put(cfg->mempool, txn);
    }

    return 0;

error_1:
    free(txn->sk_ctx);
    rte_mempool_put(cfg->mempool, txn);
error_0:
    return -1;
}

static int event_process(struct epoll_event *event, struct server_vars *sv)
{
    int ret;

    log_debug("Processing an new RX event.");
    int sockfd;

    struct fd_ctx_t *sk_ctx = (struct fd_ctx_t *)event->data.ptr;

    log_debug("sk_ctx->sockfd: %d \t sv->rpc_svr_sockfd: %d", sk_ctx->sockfd, sv->rpc_svr_sockfd);

    if (sk_ctx->fd_tp == RPC_FD || sk_ctx->fd_tp == ING_FD || sk_ctx->fd_tp == OOB_FD)
    {
        log_debug("Accepting new connection on %s.", sk_ctx->sockfd == sv->rpc_svr_sockfd ? "RPC server" : "Ingress server");
        ret = conn_accept(sk_ctx->sockfd, sv);
        if (unlikely(ret == -1))
        {
            log_error("conn_accept() error");
            return -1;
        }
    }
    else if (sk_ctx->fd_tp == RDMA_PE_FD)
    {
        doca_pe_clear_notification(g_ctx->rdma_pe, 0);
        log_info("dealing with rdma fd");
        while (doca_pe_progress(g_ctx->rdma_pe))
        {
        }
    }
    else if (sk_ctx->fd_tp == INTER_FNC_SKT_FD) {
        // do the io_rx to ensure not blocking the event loop;
        ret = rdma_write(&sockfd, sv);
        if (unlikely(ret == -1))
        {
            log_error("conn_write() error");
            return -1;
        }

    }
    else if (event->events & EPOLLIN)
    {
        if (sk_ctx->peer_svr_fd == sv->ing_svr_sockfd)
        {
            log_debug("Reading new data from external client.");
            ret = conn_read(sk_ctx->sockfd, sk_ctx);
            if (unlikely(ret == -1))
            {
                log_error("conn_read() error");
                return -1;
            }
        } else if (sk_ctx->peer_svr_fd == sv->rpc_svr_sockfd)
        {
            log_debug("Reading new data from RPC client.");
            ret = rpc_server_receive(sk_ctx->sockfd);
            if (unlikely(ret == -1))
            {
                log_error("rpc_server_receive() error");
                return -1;
            }
        } else 
        {
            log_error("Unknown peer_svr_fd");
            return -1;
        }

        if (ret == 1)
        {
            event->events |= EPOLLONESHOT;

            ret = epoll_ctl(sv->epfd, EPOLL_CTL_MOD, sk_ctx->sockfd, event);
            if (unlikely(ret == -1))
            {
                log_error("epoll_ctl() error: %s", strerror(errno));
                return -1;
            }
        }
    }
    else if (event->events & (EPOLLERR | EPOLLHUP))
    {
        /* TODO: Handle (EPOLLERR | EPOLLHUP) */
        log_error("(EPOLLERR | EPOLLHUP)");

        log_debug("Error - Close the connection.");
        ret = conn_close(sv, sk_ctx->sockfd);
        free(sk_ctx);
        if (unlikely(ret == -1))
        {
            log_error("conn_close() error");
            return -1;
        }
    }

    return 0;
}

/* TODO: Cleanup on errors */
static int server_init(struct server_vars *sv)
{
    int ret;

    doca_error_t result;
    log_info("Initializing intra-node I/O...");
    int internal_skt;
    // int sockfd_sk_msg = 0;
    // struct sockaddr_in addr;

    // for same host use ebpf, for different host use comch
    if (g_ctx->p_mode == SPRIGHT || is_gtw_on_host(g_ctx->p_mode)) {
        ret = new_io_init(0, &internal_skt);
        if (unlikely(ret == -1))
        {
            log_error("io_init() error");
            return -1;
        }
        log_debug("the internal_skt is %d", internal_skt);
        // sockfd_sk_msg = socket(AF_INET, SOCK_STREAM, 0);
        // if (unlikely(sockfd_sk_msg == -1))
        // {
        //     log_error("socket() error: %s", strerror(errno));
        //     return -1;
        // }
        //
        // addr.sin_family = AF_INET;
        // addr.sin_port = htons(8081);
        // addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        // ret = retry_connect(sockfd_sk_msg, (struct sockaddr *)&addr);
        // if (unlikely(ret == -1))
        // {
        //     log_error("connect() failed: %s", strerror(errno));
        //     return -1;
        // }
        // ret = sockmap_client();
        // if (unlikely(ret == -1))
        // {
        //     log_error("sockmap_client() error");
        //     return -1;
        // }
    }
    // initialize the rpc_server first
    if (g_ctx->p_mode != SPRIGHT) {
        log_info("init palladium oob svr");
    }
    else {
        log_info("Initializing spright Ingress and RPC server sockets...");
    }

    // the rpc_svr_port is the port fields in the node setting
    if (g_ctx->p_mode == SPRIGHT || is_gtw_on_host(g_ctx->p_mode)) {
        sv->rpc_svr_sockfd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, g_ctx->rpc_svr_port);
    }
    else {
        sv->rpc_svr_sockfd = create_server_socket(cfg->nodes[cfg->local_node_idx].dpu_addr, g_ctx->rpc_svr_port);

    }
    if (unlikely(sv->rpc_svr_sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    if (g_ctx->p_mode == SPRIGHT || is_gtw_on_host(g_ctx->p_mode)) {
        log_info("Initializing epoll...");
        sv->epfd = epoll_create1(0);
        if (unlikely(sv->epfd == -1))
        {
            log_error("epoll_create1() error: %s", strerror(errno));
            return -1;
        }
    }

    if (is_gtw_on_dpu(g_ctx->p_mode)) {
        // connect to different memory manager
        g_ctx->mm_svr_skt = sock_utils_connect(g_ctx->m_res.ip.c_str(), std::to_string(g_ctx->m_res.port).c_str());
        RUNTIME_ERROR_ON_FAIL(g_ctx->mm_svr_skt < 0, "create mm skt fail");

        uint32_t n_tanants = 0;
        receiveElement(g_ctx->mm_svr_skt, n_tanants);
        if (n_tanants != g_ctx->tenant_id_to_res.size()) {
            throw std::runtime_error("tenant number not same");
        }

        uint32_t tenant_id;
        for (size_t i = 0; i < n_tanants; i++) {
            receiveElement(g_ctx->mm_svr_skt, tenant_id);
            log_debug("receive res for tenant [%d]", tenant_id);
            auto& t_res = g_ctx->tenant_id_to_res[tenant_id];
            receiveElement(g_ctx->mm_svr_skt, t_res.mmap_start);
            log_debug("start: %d", t_res.mmap_start);
            receiveElement(g_ctx->mm_svr_skt, t_res.mmap_range);
            log_debug("range: %d", t_res.mmap_range);
            receiveData(g_ctx->mm_svr_skt, t_res.mempool_descriptor, t_res.mempool_descriptor_sz);
            print_buffer_hex(t_res.mempool_descriptor.get(), t_res.mempool_descriptor_sz);

            receiveData(g_ctx->mm_svr_skt, t_res.element_raw_ptr, t_res.n_element_raw_ptr);
            log_debug("received [%d] elements", t_res.n_element_raw_ptr);
            // for (uint64_t j = 0; j < t_res.n_element_raw_ptr; j++) {
            //     std::cout << *(t_res.element_raw_ptr.get() + j) << " ";
            //
            // }
            // std::cout << std::endl;
            receiveData(g_ctx->mm_svr_skt, t_res.receive_pool_element_raw_ptr, t_res.n_receive_pool_element_raw_ptr);
            log_debug("received [%d] elements", t_res.n_receive_pool_element_raw_ptr);
            // for (uint64_t j = 0; j < t_res.n_receive_pool_element_raw_ptr; j++) {
            //     std::cout << *(t_res.receive_pool_element_raw_ptr.get() + j) << " ";
            //
            // }
            // std::cout << std::endl;
        }

    }

    if (g_ctx->p_mode != SPRIGHT)
    {

        // for palladium use the rpc_svr_sockfd for oob conncetion;
        g_ctx->oob_skt_sv_fd = sv->rpc_svr_sockfd;


        oob_skt_init(g_ctx);
        log_info("oob ckt inited");

        log_info("Initializing RDMA and pe...");
        if (cfg->tenant_expt == 1) {
            result = open_rdma_device(g_ctx->rdma_device.c_str(), &g_ctx->rdma_dev);
            RUNTIME_ERROR_ON_FAIL(!g_ctx->comch_server_pe, "comch pe null");
            g_ctx->rdma_pe = g_ctx->comch_server_pe;

        }
        else {
            result = open_rdma_device_and_pe(g_ctx->rdma_device.c_str(), &g_ctx->rdma_dev, &g_ctx->rdma_pe);

        }
        LOG_AND_FAIL(result);

        log_info("Initializing rdma for tenants...");
        // ret = control_server_socks_init();
        for (auto &i : g_ctx->tenant_id_to_res) {

            log_info("initiating tenant %d", i.first);

            struct gateway_tenant_res& t_res = i.second;

            if (is_gtw_on_host(g_ctx->p_mode)) {
                result = create_two_side_mmap_from_local_memory(&t_res.mmap, reinterpret_cast<void*>(t_res.mmap_start), reinterpret_cast<size_t>(t_res.mmap_range), g_ctx->rdma_dev);
                if (result != DOCA_SUCCESS)
                {
                    DOCA_LOG_ERR("Failed to create DOCA mmap: %s", doca_error_get_descr(result));
                    throw std::runtime_error("create mmap failed");
                }
                log_debug("local memory map created");
            }
            else {
                result = doca_mmap_create_from_export(NULL, (const void *)t_res.mempool_descriptor.get(), t_res.mempool_descriptor_sz,
                                              g_ctx->rdma_dev, &t_res.mmap);
                LOG_AND_FAIL(result);

            }


            result = create_two_side_rc_rdma(g_ctx->rdma_dev, g_ctx->rdma_pe, &t_res.rdma, &t_res.rdma_ctx, g_ctx->gid_index, 100);
            LOG_AND_FAIL(result);
            log_info("rdma ctx initiated");


            result = init_inventory(&t_res.inv, t_res.n_buf);
            LOG_AND_FAIL(result);
            log_info("inv initiated");

            // init the data structure
            if (is_gtw_on_host(g_ctx->p_mode)) {
                init_same_node_rdma_config_cb(g_ctx);

            } else if (is_gtw_on_dpu(g_ctx->p_mode)){
                    init_dpu_rdma_config_cb(g_ctx);

            }

            result = init_two_side_rdma_callbacks(t_res.rdma, t_res.rdma_ctx, &g_ctx->rdma_cb, g_ctx->max_rdma_task_per_ctx);
            LOG_AND_FAIL(result);
            log_info("callbacks initiated");

            g_ctx->rdma_ctx_to_tenant_id[i.second.rdma_ctx] = i.second.tenant_id;

            // store the number of elements in the mempool
            // i.second.mp_elts = std::make_unique<void*[]>(i.second.n_buf);
            // use the element_addr instead

            if (is_gtw_on_host(g_ctx->p_mode)) {
                result = create_doca_bufs_from_vec(g_ctx, i.first, i.second.buf_sz, i.second.element_addr);
                log_info("get %d elements from mp", g_ctx->rr_per_ctx);
                auto tmp_ptrs = std::make_unique<void*[]>(g_ctx->rr_per_ctx);
                ret = rte_mempool_get_bulk(i.second.mp_ptr, tmp_ptrs.get(), g_ctx->rr_per_ctx);
                log_info("the first addr is %p", tmp_ptrs.get()[0]);
                if (ret != 0) {
                    throw std::runtime_error("get elements failed");
                }

                i.second.rr_element_addr.reserve(g_ctx->rr_per_ctx);
                log_info("get all the ptrs [%d]", i.second.rr_element_addr.size());
                void** begin = tmp_ptrs.get();
                for (uint32_t idx = 0; idx < g_ctx->rr_per_ctx; idx++) {
                    i.second.rr_element_addr.push_back(reinterpret_cast<uint64_t>(begin[idx]));
                }
            }
            else {
                // TODO: create from raw ptr
                result = create_doca_bufs(g_ctx, i.first, i.second.mmap_range, i.second.element_raw_ptr.get(), i.second.n_element_raw_ptr);
                i.second.rr_element_addr.reserve(g_ctx->rr_per_ctx);
                uint64_t min_sz = std::min((uint64_t)g_ctx->rr_per_ctx, i.second.n_receive_pool_element_raw_ptr);
                for (uint64_t idx = 0; idx < min_sz; idx++) {
                    i.second.rr_element_addr.push_back(*( i.second.receive_pool_element_raw_ptr.get() + idx ));

                }
                log_debug("push back to pool");
                for (uint64_t st = min_sz; st < i.second.n_receive_pool_element_raw_ptr; st++) {
                    i.second.dpu_recv_buf_pool.push(*(i.second.receive_pool_element_raw_ptr.get() + st));
                }
                log_debug("The size of recv pool is ", i.second.dpu_recv_buf_pool.size());


            }
            LOG_AND_FAIL(result);
            
            log_info("start get elements");

            log_info("get all the ptrs [%d]", i.second.rr_element_addr.size());

            g_ctx->print_gateway_ctx();

            // will call the state change automatically
            result = doca_ctx_start(i.second.rdma_ctx);
            LOG_AND_FAIL(result);
            log_info("rdma ctx for tenant [%d] started", i.first);

            // start and prepare one ctx then continue to the next;

            // TODO: add the connection number in cfg
            // connect to different nodes

            // test if exchanges can be done without running the pe
            // assuming each node have same tenant order
            // while (t_res.task_submitted) {
            //
            //     doca_pe_progress(g_ctx->rdma_pe);
            //     std::this_thread::sleep_for(std::chrono::seconds(10));
            //     log_info("g_ctx addr %p", g_ctx);
            //     g_ctx->print_gateway_ctx();
            // }
            log_info("tenant [%d] finished", i.first);

        }

        if (is_gtw_on_host(g_ctx->p_mode)) {
            struct fd_ctx_t *rdma_pe_fd_tp = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
            rdma_pe_fd_tp->fd_tp = RDMA_PE_FD;
            // add to epfd
            result = register_pe_to_ep_with_fd_tp(g_ctx->rdma_pe, sv->epfd, rdma_pe_fd_tp, g_ctx);
            if (unlikely(result != DOCA_SUCCESS))
            {
                log_error("register_pe_to_ep() error");
                return -1;
            }

        }

        // log_info("exchange rdma_info...");
        // // ret = exchange_rdma_info();
        // if (unlikely(ret == -1))
        // {
        //     log_error("exchange_rdma_node_res() error");
        //     return -1;
        // }
        //
        // log_info("control server epoll init");
        //
        // // ret = control_server_ep_init(&cfg->control_server_epfd);
        // if (unlikely(ret == -1))
        // {
        //     log_error("control_server_epfd_init() error");
        //     return -1;
        // }
        //
        // log_info("connect qps");
        // // ret = rdma_qp_connection_init();
        // if (unlikely(ret == -1))
        // {
        //     log_error("rdma_qp_connection_init() error");
        //     return -1;
        // }
    }
    if (g_ctx->receive_req) {

        //TODO: connect with ngx
        // the skt connection is moved to oob_skt_init function
    }

    if (g_ctx->p_mode == SPRIGHT || is_gtw_on_host(g_ctx->p_mode)) {
        struct epoll_event event;

        if (is_gtw_on_host(g_ctx->p_mode)) {
            struct fd_ctx_t *inter_fnc_skt_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
            inter_fnc_skt_ctx->sockfd = internal_skt;
            inter_fnc_skt_ctx->fd_tp = INTER_FNC_SKT_FD;
            g_ctx->fd_to_fd_ctx[internal_skt] = inter_fnc_skt_ctx;

            event.events = EPOLLIN;
            event.data.ptr = inter_fnc_skt_ctx;
            ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, internal_skt, &event);
            if (unlikely(ret == -1))
            {
                log_error("epoll_ctl() error: %s", strerror(errno));
                return -1;
            }

        }

        struct fd_ctx_t *rpc_svr_sk_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        rpc_svr_sk_ctx->sockfd = sv->rpc_svr_sockfd;
        rpc_svr_sk_ctx->is_server = IS_SERVER_TRUE;
        rpc_svr_sk_ctx->peer_svr_fd = -1;
        if (g_ctx->p_mode != SPRIGHT) {
            rpc_svr_sk_ctx->fd_tp = OOB_FD;
        }
        else {
            rpc_svr_sk_ctx->fd_tp = RPC_FD;
        }
        g_ctx->fd_to_fd_ctx[sv->rpc_svr_sockfd] = rpc_svr_sk_ctx;

        sv->ing_svr_sockfd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, EXTERNAL_SERVER_PORT);
        if (unlikely(sv->ing_svr_sockfd == -1))
        {
            log_error("socket() error: %s", strerror(errno));
            return -1;
        }
        struct fd_ctx_t *ing_svr_sk_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        ing_svr_sk_ctx->sockfd = sv->ing_svr_sockfd;
        ing_svr_sk_ctx->is_server = IS_SERVER_TRUE;
        ing_svr_sk_ctx->peer_svr_fd = -1;
        ing_svr_sk_ctx->fd_tp = ING_FD;
        g_ctx->fd_to_fd_ctx[sv->ing_svr_sockfd] = ing_svr_sk_ctx;
        event.events = EPOLLIN;

        event.data.ptr = rpc_svr_sk_ctx;
        ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, sv->rpc_svr_sockfd, &event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return -1;
        }

        event.data.ptr = ing_svr_sk_ctx;
        ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, sv->ing_svr_sockfd, &event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return -1;
        }
    }

    log_info("server init finished");



    return 0;
}

/* TODO: Cleanup on errors */
static int server_exit(struct server_vars *sv)
{
    int ret;

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sv->rpc_svr_sockfd, NULL);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sv->ing_svr_sockfd, NULL);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    ret = close(sv->epfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    ret = close(sv->rpc_svr_sockfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    ret = close(sv->ing_svr_sockfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }
    // destroy_control_server_socks();

    // rdma_exit();

    return 0;
}

static int server_process_rx(void *arg)
{
    struct epoll_event event[N_EVENTS_MAX];
    struct server_vars *sv = NULL;
    int n_fds;
    int ret;
    int i;

    sv = (struct server_vars*)arg;

    while (1)
    {
        log_debug("Waiting for new RX events...");
        if (g_ctx->p_mode != SPRIGHT) {
            doca_pe_request_notification(g_ctx->rdma_pe);
        }
        n_fds = epoll_wait(sv->epfd, event, N_EVENTS_MAX, -1);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return -1;
        }

        log_debug("epoll_wait() returns %d new events", n_fds);

        for (i = 0; i < n_fds; i++)
        {
            ret = event_process(&event[i], sv);
            if (unlikely(ret == -1))
            {
                log_error("event_process() error");
                return -1;
            }
        }
    }

    return 0;
}

static int palladium_host_mode_loop_with_naive_ing(void *arg)
{
    log_info("palladium host mode loop");
    struct epoll_event event[N_EVENTS_MAX];
    struct server_vars *sv = NULL;
    int n_fds;
    int ret;
    int sockfd;
    int i;

    sv = (struct server_vars*)arg;

    while (1)
    {
        log_debug("Waiting for new RX events...");
        if (g_ctx->p_mode != SPRIGHT) {
            doca_pe_request_notification(g_ctx->rdma_pe);
        }
        n_fds = epoll_wait(sv->epfd, event, N_EVENTS_MAX, 0);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return -1;
        }

        log_debug("epoll_wait() returns %d new events", n_fds);

        for (i = 0; i < n_fds; i++)
        {
            ret = event_process(&event[i], sv);
            if (unlikely(ret == -1))
            {
                log_error("event_process() error");
                return -1;
            }
        }

    }

    return 0;
}
static int server_process_tx(void *arg)
{
    log_debug("server tx");
    struct server_vars *sv = NULL;
    int sockfd;
    int ret;

    sv = (struct server_vars *)arg;

    while (1)
    {
        // the gtw dpu mode will not run the function
        // will remove this soon, the rdma is called from here 
        if (is_gtw_on_host(g_ctx->p_mode)) {
            // do the closing inside the function
            ret = rdma_write(&sockfd, sv);
        }
        else {
            // conn_write return 1 means not back to external client
            ret = conn_write(&sockfd);
        }
        if (unlikely(ret == -1))
        {
            log_error("conn_write() error");
            return -1;
        }
        else if (ret == 1)
        {
            continue;
        }

        log_debug("Closing the connection after TX.\n");
        ret = conn_close(sv, sockfd);
        if (unlikely(ret == -1))
        {
            log_error("conn_close() error");
            return -1;
        }
    }

    return 0;
}

static void metrics_collect(void)
{
    while (1)
    {
        sleep(30);
    }
}

static int gateway(char *cfg_file)
{
    // const struct rte_memzone *memzone = NULL;
    unsigned int lcore_worker[NUM_LCORES];
    struct server_vars sv;
    doca_error_t result;

    int ret;

    const char *error_messages[] = {
        "server_process_rx() error",
        "server_process_tx() error",
        "rpc_client() error",
        "rpc_server() error"
    };
    memset(peer_node_sockfds, 0, sizeof(peer_node_sockfds));

    // memzone = rte_memzone_lookup(MEMZONE_NAME);
    // if (unlikely(memzone == NULL))
    // {
    //     log_error("rte_memzone_lookup() error");
    //     goto error_0;
    // }
    //
    // cfg = (struct spright_cfg_s*)memzone->addr;
    //
    struct spright_cfg_s real_cfg;
    cfg = &real_cfg;
    ret = cfg_init(cfg_file, cfg);
    std::string mp_name;

    struct gateway_ctx gtw_ctx(cfg);
    if (unlikely(ret == -1))
    {
        log_error("cfg_init() error");
        goto error_0;
    }
    g_ctx = &gtw_ctx;
    g_ctx->print_gateway_ctx();
    g_ctx->cfg = cfg;
    if (!g_ctx->cfg) {
        throw std::runtime_error("cfg not initiated");
    }
    
    


    if (g_ctx->p_mode == SPRIGHT) {
        cfg->mempool = rte_mempool_lookup(SPRIGHT_MEMPOOL_NAME);
        if (!cfg->mempool) {
            throw std::runtime_error("spright mempool didn't found");
        }
    } else if (is_gtw_on_host(g_ctx->p_mode)) {
        for (auto& i : gtw_ctx.tenant_id_to_res) {
            mp_name = mempool_prefix + std::to_string(i.first);
            log_info("looking up %s", mp_name.c_str());
            i.second.mp_ptr = rte_mempool_lookup(mp_name.c_str());
            if (!i.second.mp_ptr) {
                throw std::runtime_error("palladium mempool didn't found");

            }

            auto [start, range] = detect_mp_gap_and_return_range(i.second.mp_ptr, &i.second.element_addr);
            log_info("tenant mp %s start: %p, range %d", mp_name.c_str(), start, range);
            i.second.mmap_start = start;
            i.second.mmap_range = range;
        }
        if (gtw_ctx.tenant_id_to_res.size() == 1) {
            // use the onlly tenant's mp
            cfg->mempool = gtw_ctx.tenant_id_to_res.begin()->second.mp_ptr;
        }

    } else if (is_gtw_on_dpu(g_ctx->p_mode)) {
        log_info("now in DPU mode and init the comch");
        result = open_doca_device_with_pci(g_ctx->comch_server_device_name.c_str(), NULL, &(g_ctx->comch_server_dev));
        LOG_AND_FAIL(result);

        result = open_doca_device_rep_with_pci(g_ctx->comch_server_dev, DOCA_DEVINFO_REP_FILTER_NET, g_ctx->comch_client_rep_device_name.c_str(),
                                               &(g_ctx->comch_client_dev_rep));
        LOG_AND_FAIL(result);

        if (cfg->tenant_expt == 1) {
            init_comch_server_cb_tenant_expt(g_ctx);

        }
        else {
            init_comch_server_cb(g_ctx);

        }

        result = init_comch_server(comch_server_name.c_str(), g_ctx->comch_server_dev, g_ctx->comch_client_dev_rep, &g_ctx->comch_server_cb, &(g_ctx->comch_server),
                                                      &(g_ctx->comch_server_pe), &(g_ctx->comch_server_ctx));
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to init cc client with error = %s", doca_error_get_name(result));
            return result;
        }

    }
    else {
        throw std::runtime_error("mode not valid");
    }

    ret = server_init(&sv);
    if (unlikely(ret == -1))
    {
        log_error("server_init() error");
        goto error_0;
    }

    for (int i = 0; i < NUM_LCORES; ++i) {
        lcore_worker[i] = (i == 0) 
            ? rte_get_next_lcore(rte_get_main_lcore(), 1, 1) 
            : rte_get_next_lcore(lcore_worker[i - 1], 1, 1);

        if (unlikely(lcore_worker[i] == RTE_MAX_LCORE)) {
            log_error("rte_get_next_lcore() error");
            goto error_1;
        }
    }

    if (is_gtw_on_dpu(g_ctx->p_mode)) {

        // ret = rte_eal_remote_launch(dpu_gateway_rx, g_ctx, lcore_worker[0]);
        // if (unlikely(ret < 0))
        // {
        //     log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
        //     goto error_1;
        // }

        // by default use rtc
        // if (cfg->tenant_expt == 1) {
        //     ret = rte_eal_remote_launch(dpu_gateway_tx_expt, g_ctx, lcore_worker[1]);
        //
        // } else {
        //     ret = rte_eal_remote_launch(dpu_gateway_tx_expt, g_ctx, lcore_worker[1]);
        // }
        ret = rte_eal_remote_launch(dpu_gateway_tx_expt, g_ctx, lcore_worker[1]);
        if (unlikely(ret < 0))
        {
            log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
            goto error_1;
        }
    }
    else if (g_ctx->p_mode == PALLADIUM_HOST) {
        ret = rte_eal_remote_launch(palladium_host_mode_loop_with_naive_ing, &sv, lcore_worker[1]);
        if (unlikely(ret < 0))
        {
            log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
            goto error_1;
        }
    }
     else if (g_ctx->p_mode == PALLADIUM_HOST_WORKER) {
        // DON't need the naive ingress
        ret = rte_eal_remote_launch(palladium_host_mode_loop_with_naive_ing, &sv, lcore_worker[1]);
        if (unlikely(ret < 0))
        {
            log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
            goto error_1;
        }

    }
    else {

        // TODO: use rtc for PGTW on the host
        ret = rte_eal_remote_launch(server_process_rx, &sv, lcore_worker[0]);
        if (unlikely(ret < 0))
        {
            log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
            goto error_1;
        }

        ret = rte_eal_remote_launch(server_process_tx, &sv, lcore_worker[1]);
        if (unlikely(ret < 0))
        {
            log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
            goto error_1;
        }
    }


    {
        metrics_collect();
    }


    for (int i = 0; i < NUM_LCORES; i++) {
        ret = rte_eal_wait_lcore(lcore_worker[i]);
        if (unlikely(ret == -1)) {
            log_error("%s", error_messages[i]);
            goto error_1;
        }
    }

    ret = server_exit(&sv);
    if (unlikely(ret == -1))
    {
        log_error("server_exit() error");
        goto error_0;
    }

    return 0;

error_1:
    server_exit(&sv);
error_0:
    return -1;
}

int main(int argc, char **argv)
{
    int level = log_set_level_from_env();
#ifdef DEBUG
    printf("debug mode!!!");
    log_set_level(1);
    level = 1;
    
#endif
    enum my_log_level lv = static_cast<enum my_log_level>(level);

    doca_error_t result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, my_log_level_to_doca_log_level(lv));
    LOG_ON_FAILURE(result);

    int ret;

    ret = rte_eal_init(argc, argv);
    if (unlikely(ret == -1))
    {
        log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
        goto error_0;
    }
    argc -= ret;
    argv += ret;

    if (unlikely(argc == 1))
    {
        log_error("Configuration file not provided");
        goto error_1;
    }
    // while(true) {}

    ret = gateway(argv[1]);
    if (unlikely(ret == -1))
    {
        log_error("gateway() error");
        goto error_1;
    }

    ret = rte_eal_cleanup();
    if (unlikely(ret < 0))
    {
        log_error("rte_eal_cleanup() error: %s", rte_strerror(-ret));
        goto error_0;
    }

    return 0;

error_1:
    rte_eal_cleanup();
error_0:
    return 1;
}
