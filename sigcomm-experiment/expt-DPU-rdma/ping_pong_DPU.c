#define _GNU_SOURCE
#include "ib.h"
#include "log.h"
#include "qp.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MR_SIZE 10240

int main(int argc, char *argv[])
{
    struct ib_ctx ctx;

    static struct option long_options[] = {{"server_ip", required_argument, NULL, 'H'},
                                           {"port", required_argument, NULL, 'p'},
                                           {"local_ip", required_argument, NULL, 'L'},
                                           {"sgid_index", required_argument, 0, 'x'},
                                           {"help", no_argument, 0, 'h'},
                                           {"device_index", required_argument, 0, 'd'},
                                           {"ib_port", required_argument, 0, 'i'},
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

    char *port = NULL;
    while ((ch = getopt_long(argc, argv, "H:p:L:hi:d:x:", long_options, &option_index)) != -1)
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
        case '?':
            printf("options error\n");
            exit(1);
        }
    }
    // on xl170, the device_idx should be 3, on c6525-25g, the device_idx should be 2.

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

    int ret = 0;
    if (is_server)
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);

        ret = post_srq_recv(ctx.srq, local_res.mrs[1].addr, local_res.mrs[1].length, local_res.mrs[1].lkey, 0);
        if (ret != RDMA_SUCCESS)
        {
            log_error("post recv request failed");
        }
        const char *test_str = "Hello, world!";

        strncpy(local_res.mrs[0].addr, test_str, MR_SIZE);

        ret =
            post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, 0, 0);

        struct ibv_wc wc;
        int wc_num = 0;
        do
        {
        } while ((wc_num = ibv_poll_cq(ctx.send_cq, 1, &wc) == 0));
        printf("Got send cqe!!\n");

        do
        {
        } while ((wc_num = ibv_poll_cq(ctx.recv_cq, 1, &wc) == 0));
        printf("Got recv cqe!!\n");
        printf("Received string from Client: %s\n", (char *)local_res.mrs[1].addr);
        close(self_fd);
        close(peer_fd);
    }
    else
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);
        printf("post share receive queue\n");
        // prepost receive request
        ret = post_srq_recv(ctx.srq, local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, 0);
        if (ret != RDMA_SUCCESS)
        {
            log_debug("post recv request failed");
        }
        printf("wait for incoming request\n");

        struct ibv_wc wc;
        int wc_num = 0;
        // poll to get the completion event from recv_cq
        do
        {
        } while ((wc_num = ibv_poll_cq(ctx.recv_cq, 1, &wc) == 0));
        printf("Got recv cqe!!\n");
        printf("Received string from Server: %s\n", (char *)local_res.mrs[0].addr);

        // it is a good practice to post receive request after it is consumed.
        // In this example this one will not be consumed
        ret = post_srq_recv(ctx.srq, local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, 0);
        if (ret != RDMA_SUCCESS)
        {
            log_error("post recv request failed");
        }

        ret =
            post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, 0, 0);
        // poll the send_cq for the ack of send.
        do
        {
        } while ((wc_num = ibv_poll_cq(ctx.send_cq, 1, &wc) == 0));
        printf("Got send cqe!!\n");

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
