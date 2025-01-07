#include <math.h>
#define _GNU_SOURCE
#include "ib.h"
#include "log.h"
#include "qp.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <fcntl.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif
#define MR_SIZE 10240
#define NS_PER_SEC 1E9  /* Nano-seconds per second */
#define NS_PER_MSEC 1E6 /* Nano-seconds per millisecond */

static double calculate_timediff_ms(struct timespec *end, struct timespec *start)
{
    long diff;

    diff = (end->tv_sec - start->tv_sec) * NS_PER_SEC;
    diff += end->tv_nsec;
    diff -= start->tv_nsec;

    return (double)(diff / NS_PER_MSEC);
}
int main(int argc, char *argv[])
{
    struct ib_ctx ctx;
    log_set_level(LOG_INFO);

    static struct option long_options[] = {{"server_ip", required_argument, NULL, 'H'},
                                           {"port", required_argument, NULL, 'p'},
                                           {"local_ip", required_argument, NULL, 'L'},
                                           {"sgid_index", required_argument, 0, 'x'},
                                           {"help", no_argument, 0, 'h'},
                                           {"device_index", required_argument, 0, 'd'},
                                           {"ib_port", required_argument, 0, 'i'},
                                           {"msg_size", required_argument, 0, 's'},
                                           {"iter", required_argument, 0, 'n'},
                                           {0, 0, 0, 0}};
    int option_index = 0;

    int ch = 0;
    bool is_server = true;
    char *server_name = NULL;
    char *local_ip = NULL;
    char *usage = "";
    int ib_port = 0;
    int device_idx = 0;
    int sgid_idx = 0;
    int msg_sz = 0;
    int iter = 0;

    char *port = "10000";
    while ((ch = getopt_long(argc, argv, "H:L:p:hi:d:x:n:s:", long_options, &option_index)) != -1)
    {
        switch (ch)
        {
        case 'H':
            is_server = false;
            server_name = strdup(optarg);
            break;
        case 'L':
            local_ip = strdup(optarg);
            break;
        case 'p':
            port = strdup(optarg);
            break;
        case 'h':
            printf("usage: %s", usage);
            break;
        case 'i':
            ib_port = atoi(optarg);
            break;
        case 'd':
            device_idx = atoi(optarg);
            break;
        case 'x':
            sgid_idx = atoi(optarg);
            break;
        case 's':
            msg_sz = atoi(optarg);
            break;
        case 'n':
            iter = atoi(optarg);
            break;

        case '?':
            printf("options error\n");
            exit(1);
        }
    }

    struct rdma_param rparams = {
        .device_idx = device_idx,
        .sgid_idx = sgid_idx,
        .ib_port = ib_port,
        .qp_num = 1,
        .remote_mr_num = 2,
        .remote_mr_size = MR_SIZE,
        .init_cqe_num = 128,
        .max_send_wr = 100,
        .n_send_wc = 10,
        .n_recv_wc = 10,
    };

    void **buffers = (void **)calloc(rparams.remote_mr_num, sizeof(void *));
    assert(buffers);
    void *buf = (void *)calloc(rparams.remote_mr_num, rparams.remote_mr_size);
    assert(buf);
    for (size_t i = 0; i < rparams.remote_mr_num; i++)
    {
        buffers[i] = buf + i * rparams.remote_mr_size;
    }
    init_ib_ctx(&ctx, &rparams, NULL, buffers);

#ifdef DEBUG

    printf("max_mr: %d\n", ctx.device_attr.max_mr);
    printf("max_mr_size: %lu\n", ctx.device_attr.max_mr_size);
    printf("page_size_cap: %lu\n", ctx.device_attr.page_size_cap);
#endif
    printf("Hello, World!\n");

    int self_fd = 0;
    int peer_fd = 0;
    struct sockaddr_in peer_addr;

    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    struct ib_res remote_res;
    struct ib_res local_res;
    init_local_ib_res(&ctx, &local_res);
    if (is_server)
    {

        self_fd = sock_utils_bind(local_ip, port);
        assert(self_fd > 0);
        listen(self_fd, 5);
        peer_fd = accept(self_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        assert(peer_fd > 0);

        recv_ib_res(&remote_res, peer_fd);
        send_ib_res(&local_res, peer_fd);
    }
    else
    {
        peer_fd = sock_utils_connect(server_name, port);
        send_ib_res(&local_res, peer_fd);
        recv_ib_res(&remote_res, peer_fd);
    }

#ifdef DEBUG

    printf("remote qp_nums\n");
    for (size_t i = 0; i < remote_res.n_qp; i++)
    {
        printf("%d\n", remote_res.qp_nums[i]);
    }
    printf("local qp_nums\n");
    for (size_t i = 0; i < ctx.qp_num; i++)
    {
        printf("%d\n", local_res.qp_nums[i]);
    }
    printf("remote mr info\n\n");
    for (size_t i = 0; i < remote_res.n_mr; i++)
    {
        printf("mr length %lu\n", remote_res.mrs[i].length);
        printf("mr addrs %p\n", remote_res.mrs[i].addr);
        printf("mr lkey %d\n", remote_res.mrs[i].lkey);
        printf("mr rkey %d\n", remote_res.mrs[i].rkey);
    }
    printf("local mr len\n\n");
    for (size_t i = 0; i < ctx.qp_num; i++)
    {
        printf("mr length %lu\n", local_res.mrs[i].length);
        printf("mr addrs %p\n", local_res.mrs[i].addr);
        printf("mr lkey %d\n", local_res.mrs[i].lkey);
        printf("mr rkey %d\n", local_res.mrs[i].rkey);
    }

#endif /* ifdef DEBUG */

    struct timespec start_time;
    struct timespec end_time;

    int ret = 0;
    if (is_server)
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);

        ret = post_srq_recv(ctx.srq, local_res.mrs[1].addr, msg_sz, local_res.mrs[1].lkey, 0);
        if (ret != RDMA_SUCCESS)
        {
            log_error("post recv request failed");
        }
        const char *test_str = "Hello, world!";

        ret = ibv_req_notify_cq(ctx.send_cq, 0);
        if (ret)
        {
            log_error("could not create send CQ notification");
        }
        ret = ibv_req_notify_cq(ctx.recv_cq, 0);
        if (ret)
        {
            log_error("could not create recv CQ notification");
        }
        int flags;
        flags = fcntl(ctx.send_channel->fd, F_GETFL);
        ret = fcntl(ctx.send_channel->fd, F_SETFL, flags | O_NONBLOCK);
        if (ret < 0)
        {
            log_error("failed to change the file descriptor");
        }
        flags = fcntl(ctx.recv_channel->fd, F_GETFL);
        ret = fcntl(ctx.recv_channel->fd, F_SETFL, flags | O_NONBLOCK);
        if (ret < 0)
        {
            log_error("failed to change the file descriptor");
        }

        int send_fd = ctx.send_channel->fd;
        int ep = epoll_create1(0);
        int recv_fd = ctx.recv_channel->fd;
        assert(ep > 0);

        struct epoll_event ep_ev_sd = {
            .events = EPOLLIN,
            .data.ptr = ctx.send_channel,
        };
        struct epoll_event ep_ev_rc = {
            .events = EPOLLIN,
            .data.ptr = ctx.recv_channel,
        };
        epoll_ctl(ep, EPOLL_CTL_ADD, send_fd, &ep_ev_sd);
        epoll_ctl(ep, EPOLL_CTL_ADD, recv_fd, &ep_ev_rc);

        strncpy(local_res.mrs[0].addr, test_str, MR_SIZE);

        if (clock_gettime(CLOCK_TYPE_ID, &start_time) != 0)
        {
            log_error("failed to get start tiem");
        }
        // start by post first send req

        int remain_iter = iter;
        struct ibv_wc wc[5];
        int wc_num = 0;
        ret = post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, msg_sz, local_res.mrs[0].lkey,
                                 remain_iter, 0);
        // In this example, there should be two completion event generate.
        // One from the send_cq(the completion of post_send)
        // One from the recv_cq(The completion of client send)
        while (true)
        {
            struct epoll_event events[2];
            // wait for the epoll with maximum 2 event
            int n = epoll_wait(ep, events, 2, -1);
            if (n < 0)
            {
                log_error("epoll wait error");
            }
            for (size_t i = 0; i < n; i++)
            {
                if (events[i].events & EPOLLIN)
                {
                    struct ibv_cq *ev_cq;

                    void *ev_ctx;
                    // get the corresponding CQ from the completion channel
                    // ev_ctx does not have meaning here because we don't set CQ context when we crate CQ.
                    ret = ibv_get_cq_event(events[i].data.ptr, &ev_cq, &ev_ctx);
                    if (ret)
                    {
                        fprintf(stderr, "Failed to get CQ event\n");
                        return -1;
                    }

                    /* Acknowledge the CQ event */
                    ibv_ack_cq_events(ev_cq, 1);

                    /* Re-request CQ notifications */
                    // avoid receive live lock
                    ret = ibv_req_notify_cq(ev_cq, 0);
                    if (ret)
                    {
                        fprintf(stderr, "Couldn't request CQ notification\n");
                        return -1;
                    }
                    // consume all elements from the completion queue.
                    // The elements could be consumed in previous poll
                    do
                    {
                        wc_num = ibv_poll_cq(ev_cq, 5, wc);
                        if (wc_num < 0)
                        {
                            log_error("poll cq error");
                            exit(1);
                        }
                        if (ev_cq == ctx.send_cq)
                        {
                        }
                        else if (ev_cq == ctx.recv_cq)
                        {
                            for (size_t j = 0; j < wc_num; j++)
                            {
                                if (wc[j].status != IBV_WC_SUCCESS)
                                {
                                    log_error("recv cq error");
                                }
                                remain_iter--;
                                if (remain_iter == 0)
                                {
                                    goto finish;
                                }
                                ret = post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, msg_sz,
                                                         local_res.mrs[0].lkey, remain_iter, 0);
                                if (ret != RDMA_SUCCESS)
                                {
                                    log_error("post recv request: [%d] failed", remain_iter);
                                    exit(1);
                                }
                                /* log_debug("post [%d] send req", remain_iter); */
                                ret = post_srq_recv(ctx.srq, local_res.mrs[1].addr, msg_sz,
                                                    local_res.mrs[1].lkey, 0);
                                if (ret != RDMA_SUCCESS)
                                {
                                    log_error("post recv request failed");
                                    exit(1);
                                }
                            }
                        }
                    } while (wc_num > 0);
                }
            }
        }
    finish:

        if (clock_gettime(CLOCK_TYPE_ID, &end_time) != 0)
        {
            log_error("failed to get end tiem");
        }

        log_info("rdma_interrupt_lat_server,%d,%u,%0.4f (type,cnt,msg_sz,milliseconds)", iter, msg_sz,
                 calculate_timediff_ms(&end_time, &start_time));
        close(ep);
        close(self_fd);
        close(peer_fd);
    }
    else
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);
        printf("post share receive queue\n");
        ret = post_srq_recv(ctx.srq, local_res.mrs[0].addr, msg_sz, local_res.mrs[0].lkey, 0);
        if (ret != RDMA_SUCCESS)
        {
            log_debug("post recv request failed");
        }
        printf("wait for incoming request\n");

        int remain_iter = iter;
        int wr_id = iter;

        ret = ibv_req_notify_cq(ctx.send_cq, 0);
        if (ret)
        {
            log_error("could not create send CQ notification");
        }
        ret = ibv_req_notify_cq(ctx.recv_cq, 0);
        if (ret)
        {
            log_error("could not create recv CQ notification");
        }
        int flags;
        // set the fd to be nonblocking
        flags = fcntl(ctx.send_channel->fd, F_GETFL);
        ret = fcntl(ctx.send_channel->fd, F_SETFL, flags | O_NONBLOCK);
        if (ret < 0)
        {
            log_error("failed to change the file descriptor");
        }
        flags = fcntl(ctx.recv_channel->fd, F_GETFL);
        ret = fcntl(ctx.recv_channel->fd, F_SETFL, flags | O_NONBLOCK);
        if (ret < 0)
        {
            log_error("failed to change the file descriptor");
        }
        int ep = epoll_create1(0);
        int send_fd = ctx.send_channel->fd;
        int recv_fd = ctx.recv_channel->fd;
        assert(ep > 0);

        struct epoll_event ep_ev_sd = {
            .events = EPOLLIN,
            .data.ptr = ctx.send_channel,
        };
        struct epoll_event ep_ev_rc = {
            .events = EPOLLIN,
            .data.ptr = ctx.recv_channel,
        };
        epoll_ctl(ep, EPOLL_CTL_ADD, send_fd, &ep_ev_sd);
        epoll_ctl(ep, EPOLL_CTL_ADD, recv_fd, &ep_ev_rc);

        struct ibv_wc wc[5];
        int wc_num = 0;
        while (true)
        {
            struct epoll_event events[5];
            // wait for the epoll with maximum 2 event
            int n = epoll_wait(ep, events, 5, -1);
            if (n < 0)
            {
                log_error("epoll wait error");
            }
            for (size_t i = 0; i < n; i++)
            {
                if (events[i].events & EPOLLIN)
                {
                    struct ibv_cq *ev_cq;

                    void *ev_ctx;
                    // get the corresponding CQ from the completion channel
                    // ev_ctx does not have meaning here because we don't set CQ context when we crate CQ.
                    ret = ibv_get_cq_event(events[i].data.ptr, &ev_cq, &ev_ctx);
                    if (ret)
                    {
                        fprintf(stderr, "Failed to get CQ event\n");
                        return -1;
                    }

                    /* Acknowledge the CQ event */
                    ibv_ack_cq_events(ev_cq, 1);

                    /* Re-request CQ notifications */
                    // avoid receive live lock
                    ret = ibv_req_notify_cq(ev_cq, 0);
                    if (ret)
                    {
                        fprintf(stderr, "Couldn't request CQ notification\n");
                        return -1;
                    }
                    // consume all elements from the completion queue.
                    // The elements could be consumed in previous poll
                    do
                    {
                        wc_num = ibv_poll_cq(ev_cq, 5, wc);
                        if (wc_num < 0)
                        {
                            log_error("poll cq error");
                            exit(1);
                        }
                        if (ev_cq == ctx.recv_cq)
                        {
                            for (size_t j = 0; j < wc_num; j++)
                            {
                                if (wc[j].status != IBV_WC_SUCCESS)
                                {
                                    log_error("recv cq error");
                                }
                                wr_id--;
                                ret = post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, msg_sz,
                                                         local_res.mrs[0].lkey, wr_id, 0);
                                if (ret != RDMA_SUCCESS)
                                {
                                    log_error("post recv request: [%d] failed", wr_id);
                                    exit(1);
                                }
                                /* log_debug("post [%d] send req", wr_id); */
                                ret = post_srq_recv(ctx.srq, local_res.mrs[1].addr, msg_sz,
                                                    local_res.mrs[1].lkey, 0);
                                if (ret != RDMA_SUCCESS)
                                {
                                    log_error("post recv request failed");
                                    exit(1);
                                }
                            }
                        }
                        if (ev_cq == ctx.send_cq)
                        {
                            for (size_t j = 0; j < wc_num; j++)
                            {
                                remain_iter--;
                                if (remain_iter == 0)
                                {
                                    goto finish_client;
                                }
                            }
                        }
                    } while (wc_num > 0);
                }
            }
        }

    finish_client:
        log_info("finish successfully");
        close(ep);
        close(peer_fd);
    }
    free(server_name);
    free(local_ip);
    free(port);
    destroy_ib_res((&local_res));
    destroy_ib_res((&remote_res));
    destroy_ib_ctx(&ctx);
    free(buf);
    free(buffers);
    return 0;
}
