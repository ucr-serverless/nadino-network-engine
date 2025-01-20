/*
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
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_memzone.h>

#include "RDMA_utils.h"
#include "common_doca.h"
#include "control_server.h"
#include "doca_error.h"
#include "doca_pe.h"
#include "http.h"
#include "io.h"
#include "log.h"
#include "rdma_common_doca.h"
#include "spright.h"
#include "timer.h"
#include "utility.h"
#include <unordered_map>
#include <utility>
#include "palladium_doca_common.h"

DOCA_LOG_REGISTER(PALLADIUM_GATEWAY::MAIN);
#define IS_SERVER_TRUE 1
#define IS_SERVER_FALSE 0

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

    uint8_t peer_node_idx = get_node(txn->next_fn);

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

static int conn_read(int sockfd, void* sk_ctx)
{
    struct http_transaction *txn = NULL;
    int ret;

    ret = rte_mempool_get(cfg->mempool, (void **)&txn);
    if (unlikely(ret < 0))
    {
        log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
        goto error_0;
    }

    txn->is_rdma_remote_mem = 0;

    log_debug("Receiving from External User.");
    txn->length_request = read(sockfd, txn->request, HTTP_MSG_LENGTH_MAX);
    if (unlikely(txn->length_request == -1))
    {
        log_error("read() error: %s", strerror(errno));
        goto error_1;
    }

    txn->sockfd = sockfd;
    txn->sk_ctx = sk_ctx;

    // TODO: parse tenant ID from HTTP request,
    // use "0" as the default tenant ID for now.
    txn->tenant_id = 0;

    parse_route_id(txn);

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
static int rdma_write(int *sockfd)
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
        ret = rdma_send(txn, g_ctx, 0);
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
    ret = io_init();
    if (unlikely(ret == -1))
    {
        log_error("io_init() error");
        return -1;
    }
    // initialize the rpc_server first
    if (cfg->use_rdma == 1) {
        log_info("init oob svr");
    }
    else {
        log_info("Initializing Ingress and RPC server sockets...");
    }
    sv->rpc_svr_sockfd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, g_ctx->rpc_svr_port);
    if (unlikely(sv->rpc_svr_sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    if (cfg->use_rdma == 1)
    {

        g_ctx->oob_skt_sv_fd = sv->rpc_svr_sockfd;
        // TODO: connect all worker nodes using skt


        oob_skt_init(g_ctx);
        log_info("oob ckt inited");
        log_info("Initializing RDMA and pe...");
        result = open_rdma_device_and_pe(g_ctx->rdma_device.c_str(), &g_ctx->rdma_dev, &g_ctx->rdma_pe);
        LOG_AND_FAIL(result);

        log_info("Initializing rdma for tenants...");
        // ret = control_server_socks_init();
        for (auto &i : g_ctx->tenant_id_to_res) {

            log_info("initiating tenant %d", i.first);

            auto & t_res = i.second;
            result = create_two_side_mmap_from_local_memory(&t_res.mmap, reinterpret_cast<void*>(t_res.mmap_start), reinterpret_cast<size_t>(t_res.mmap_range), g_ctx->rdma_dev);
            if (result != DOCA_SUCCESS)
            {
                DOCA_LOG_ERR("Failed to create DOCA mmap: %s", doca_error_get_descr(result));
                throw std::runtime_error("create mmap failed");
            }
            log_debug("memory map created");
            // TODO: fix the max connection here
            // need total connections for a tenant
            result = create_two_side_rc_rdma(g_ctx->rdma_dev, g_ctx->rdma_pe, &t_res.rdma, &t_res.rdma_ctx, g_ctx->gid_index, 100);
            LOG_AND_FAIL(result);
            log_info("rdma ctx initiated");

            result = init_inventory(&t_res.inv, t_res.n_buf);
            LOG_AND_FAIL(result);
            log_info("inv initiated");

            // init the data structure
            init_same_node_rdma_config_cb(g_ctx);

            result = init_two_side_rdma_callbacks(t_res.rdma, t_res.rdma_ctx, &g_ctx->rdma_cb, g_ctx->max_rdma_task_per_ctx);
            LOG_AND_FAIL(result);
            log_info("callbacks initiated");

            g_ctx->rdma_ctx_to_tenant_id[i.second.rdma_ctx] = i.second.tenant_id;

            // store the number of elements in the mempool
            // i.second.mp_elts = std::make_unique<void*[]>(i.second.n_buf);
            // use the element_addr instead

            result = create_doca_bufs_from_vec(g_ctx, i.first, i.second.buf_sz, i.second.element_addr);
            LOG_AND_FAIL(result);
            
            log_info("start get elements");
            // TODO: post rr
            // TODO: change the inital rr reques
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
            log_info("get all the ptrs [%d]", i.second.rr_element_addr.size());

            g_ctx->print_gateway_ctx();

            result = doca_ctx_start(i.second.rdma_ctx);
            LOG_AND_FAIL(result);
            log_info("rdma ctx for tenant [%d] started", i.first);

            // start and prepare one ctx then continue to the next;
            t_res.task_submitted = false;

            // TODO: add the connection number in cfg
            // connect to different nodes

            // test if exchanges can be done without running the pe
            // assuming each node have same tenant order
            while (t_res.task_submitted == false) {
                doca_pe_progress(g_ctx->rdma_pe);
            }
            log_info("tenant [%d] finished", i.first);

        }

        struct fd_ctx_t *rdma_pe_fd_tp = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        rdma_pe_fd_tp->fd_tp = ING_FD;
        g_ctx->fd_to_fd_ctx[sv->ing_svr_sockfd] = rdma_pe_fd_tp;
        // add to epfd
        result = register_pe_to_ep(g_ctx->rdma_pe, sv->epfd, rdma_pe_fd_tp);
        if (unlikely(result != DOCA_SUCCESS))
        {
            log_error("control_server_socks_init() error");
            return -1;
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

    struct fd_ctx_t *rpc_svr_sk_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    rpc_svr_sk_ctx->sockfd = sv->rpc_svr_sockfd;
    rpc_svr_sk_ctx->is_server = IS_SERVER_TRUE;
    rpc_svr_sk_ctx->peer_svr_fd = -1;
    if (g_ctx->cfg->use_rdma == 1) {
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

    log_info("Initializing epoll...");
    sv->epfd = epoll_create1(0);
    if (unlikely(sv->epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return -1;
    }

    struct epoll_event event;
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
        if (cfg->use_rdma == 1) {
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

static int server_process_tx(void *arg)
{
    struct server_vars *sv = NULL;
    int sockfd;
    int ret;

    sv = (struct server_vars *)arg;

    while (1)
    {
        if (cfg->use_rdma == 1) {
            ret = rdma_write(&sockfd);
        }
        else {
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
    int NUM_LCORES = 4;
    unsigned int lcore_worker[NUM_LCORES];
    struct server_vars sv;
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
    
    


    if (cfg->use_rdma == 0) {
        cfg->mempool = rte_mempool_lookup(SPRIGHT_MEMPOOL_NAME);
        if (!cfg->mempool) {
            throw std::runtime_error("spright mempool didn't found");
        }
    } else if (cfg->memory_manager.is_remote_memory == 0) {
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

    } else {
        throw std::runtime_error("not implemented");

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

    if (cfg->use_rdma == 1)
    {
        // ret = rte_eal_remote_launch(rdma_one_side_rpc_client, NULL, lcore_worker[2]);
        // if (unlikely(ret < 0))
        // {
        //     log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
        //     goto error_1;
        // }
        //
        // ret = rte_eal_remote_launch(rdma_one_side_rpc_server, NULL, lcore_worker[3]);
        // if (unlikely(ret < 0))
        // {
        //     log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
        //     goto error_1;
        // }
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
    enum my_log_level lv = static_cast<enum my_log_level>(level);

    doca_error_t result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, my_log_level_to_doca_log_level(lv));
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
