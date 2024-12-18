#define _GNU_SOURCE
#include "ib.h"
#include "qp.h"
#include "log.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include <assert.h>
#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <bits/time.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <threads.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>

#define MR_SIZE 1024
#define THREAD_SZ_MAX 128

struct thread_arg {
    int thread_id;
    struct ib_ctx* ctx;
    struct ib_res* local_res;
};
pthread_mutex_t qp_lock;

char buf[MR_SIZE * THREAD_SZ_MAX];
pthread_t threads[THREAD_SZ_MAX];
struct thread_arg args[THREAD_SZ_MAX];
uint64_t tt_pkt_cnt = 0;
uint64_t send_time = 0;
uint64_t pkt_limit = 100000;
uint8_t ntf_frqcy = 4;
uint8_t ntf_gap = 0;

void set_thread_affinity(pthread_t thread, int core_id) {
    cpu_set_t cpuset;               // Define a CPU set
    CPU_ZERO(&cpuset);              // Clear the CPU set
    CPU_SET(core_id, &cpuset);      // Add the desired core to the set

    // Set the affinity of the thread to the specified CPU core
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np failed");
        exit(1);
    }
}

void* thread_send(void *arg)
{
    int thread_id = ((struct thread_arg*)arg)->thread_id;
    struct ib_ctx* ctx = ((struct thread_arg*)arg)->ctx;
    struct ib_res* local_res = ((struct thread_arg*)arg)->local_res;

    struct ibv_wc wc;
    int ret = 0;
    int wc_num = 0;
    do {
        pthread_mutex_lock(&qp_lock);
        if (tt_pkt_cnt == pkt_limit-1) {
            pthread_mutex_unlock(&qp_lock);
            log_info("thread %d exited\n", thread_id);
            pthread_exit(NULL);
        }
        /* ret = post_srq_recv(ctx->srq, local_res->mrs[0].addr, local_res->mrs[0].length, local_res->mrs[0].lkey, 0); */
        /* if (ret != RDMA_SUCCESS) */
        /* { */
        /*     log_debug("post recv request failed"); */
        /* } */
        if (ntf_gap == ntf_frqcy) {
            ret = post_send_signaled(ctx->qps[0], local_res->mrs[thread_id].addr, local_res->mrs[thread_id].length, local_res->mrs[thread_id].lkey, ntf_gap, 0);
            if (ret != RDMA_SUCCESS) {
                log_error("Send signaled failed");
            }
            do
            {
                wc_num = ibv_poll_cq(ctx->send_cq, 1, &wc);
            } while (wc_num == 0);
            ntf_gap = 0;
        }
        else {
            ret = post_send_unsignaled(ctx->qps[0], local_res->mrs[thread_id].addr, local_res->mrs[thread_id].length, local_res->mrs[thread_id].lkey, ntf_gap, 0);
            if (ret != RDMA_SUCCESS) {
                log_error("Send unsignaled failed");
            }
            ntf_gap++;
        }
        /* do */
        /* { */
        /* } while ((wc_num = ibv_poll_cq(ctx->recv_cq, 1, &wc) == 0)); */

        tt_pkt_cnt++;
        // log_debug("Thread id %d send %ld pkt\n", thread_id, tt_pkt_cnt);
        pthread_mutex_unlock(&qp_lock);
        sched_yield();

    } while(true);
}

int main(int argc, char *argv[])
{
    struct ib_ctx ctx;

    static struct option long_options[] = {
        {"server_ip", required_argument, NULL, 1},
        {"port", required_argument, NULL, 2},
        {"local_ip", required_argument, NULL, 3},
        {"thread_sz", required_argument, 0, 't'},
        {"sgid_index", required_argument, 0, 'x'},
        {"help", no_argument, 0, 'h'},
        {"device_index", required_argument, 0, 'd'},
        {"ib_port", required_argument, 0, 'i'},
        {"pkt_number", no_argument, 0, 'p'},
        {"single_no_lock", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    int ch = 0;
    bool is_server = true;
    char *server_name = NULL;
    char *local_ip = NULL;
    int thread_sz = 0;
    int ib_port = 0;
    int device_idx = 0;
    int sgid_idx = 0;
    bool single_no_lock = false;

    char *usage = "";

    char *port = NULL;
    while ((ch = getopt_long(argc, argv, "h:i:d:x:t:p:l", long_options, &option_index)) != -1)
    {
        switch (ch)
        {
        case 1:
            is_server = false;
            server_name = strdup(optarg);
            break;
        case 3:
            local_ip = strdup(optarg);
            break;
        case 2:
            port = strdup(optarg);
            break;
        case 't':
            thread_sz = atoi(optarg);
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
        case 'p':
            pkt_limit = atoi(optarg);
            break;
        case 'l':
            single_no_lock = true;
            break;
        case '?':
            printf("options error\n");
            printf("usage: %s", usage);
            exit(1);
        }
    }
    // on xl170, the device_idx should be 3, on c6525-25g, the device_idx should be 2.

    if (thread_sz > THREAD_SZ_MAX) {
        printf("There are %d threads, maybe too much!!!", thread_sz);
    }
    struct rdma_param rparams = {
        .device_idx = device_idx,
        .sgid_idx = sgid_idx,
        .ib_port = ib_port,
        .qp_num = 1,
        .remote_mr_num = thread_sz,
        .remote_mr_size = MR_SIZE,
        .init_cqe_num = 128,
        .max_send_wr = 128,
        .n_send_wc = 10,
        .n_recv_wc = 10,
    };

    void **buffers = (void **)calloc(rparams.remote_mr_num, sizeof(void *));
    assert(buffers);
    for (size_t i = 0; i < rparams.remote_mr_num; i++)
    {
        buffers[i] = buf + i * rparams.remote_mr_size;
    }
    init_ib_ctx(&ctx, &rparams, NULL, buffers);

    ntf_frqcy = 127;
    log_info("ntf_frqcy is %d", ntf_frqcy);

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
    log_debug("the number of cqe is %d\n", ctx.send_cqe);
    if (is_server)
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);

        struct timespec start, end;
        int wc_num = 0;
        for (size_t i = 0; i < 100; i++) {
            ret = post_srq_recv(ctx.srq, local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, i);
            if (ret != RDMA_SUCCESS)
            {
                log_error("post recv request failed");
            }
        }
        struct ibv_wc wc[100];

        assert(tt_pkt_cnt < pkt_limit - 1);
        clock_gettime(CLOCK_MONOTONIC, &start);
        while(tt_pkt_cnt != pkt_limit - 1){
            do
            {
                wc_num = ibv_poll_cq(ctx.recv_cq, 100, wc);
            } while (wc_num == 0);
            if (wc_num < 0) {
                log_error("ibv_poll_cq error");
            }
            for (size_t i = 0; i < wc_num; i++) {
                ret = post_srq_recv(ctx.srq, local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, wc[i].wr_id);
                if (ret != RDMA_SUCCESS)
                {
                    log_error("post recv request failed");
                }
            }
            // log_debug("received %d cq\n", wc_num);
            /* ret = */
            /*     post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, 0, 0); */
            /* do */
            /* { */
            /* } while ((wc_num = ibv_poll_cq(ctx.send_cq, 1, &wc) == 0)); */
            tt_pkt_cnt+=wc_num;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        double seconds = end.tv_sec - start.tv_sec;
        double nanosecond = end.tv_nsec - start.tv_nsec;

        // the unit for throughput is MB/s
        double through_put = pkt_limit * MR_SIZE / (seconds + nanosecond / 1e9) / 1024 / 1024;
        printf("Total through_put: %f MB/s\n", through_put);
        close(self_fd);
        close(peer_fd);
    }
    else
    {
        modify_qp_init_to_rts(ctx.qps[0], &local_res, &remote_res, remote_res.qp_nums[0]);

        if (single_no_lock) {

            
            struct ibv_wc wc;
            int wc_num = 0;
            do {
                if (tt_pkt_cnt == pkt_limit-1) {
                    break;
                }
                if (ntf_gap == ntf_frqcy) {
                    ret = post_send_signaled(ctx.qps[0], local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, ntf_gap, 0);
                    if (ret != RDMA_SUCCESS) {
                        log_error("post signaled send fail");
                    }
                    do
                    {
                        wc_num = ibv_poll_cq(ctx.send_cq, 1, &wc);
                    } while (wc_num == 0);
                    ntf_gap = 0;
                }
                else {
                    ret = post_send_unsignaled(ctx.qps[0], local_res.mrs[0].addr, local_res.mrs[0].length, local_res.mrs[0].lkey, ntf_gap, 0);
                    if (ret != RDMA_SUCCESS) {
                        log_error("post unsignaled send fail");
                    }
                    ntf_gap++;
                }
                tt_pkt_cnt++;
                // log_debug("send out pkt %ld\n", tt_pkt_cnt);

            } while(true);
        }
        else {
            assert(tt_pkt_cnt < pkt_limit - 1);
            if (pthread_mutex_init(&qp_lock, NULL) != 0) {
                log_error("init failed");
                exit(1);
            }


            for (size_t i = 0; i < thread_sz; i++){
                args[i].thread_id = i;
                args[i].ctx = &ctx;
                args[i].local_res = &local_res;
                ret = pthread_create(&threads[i], NULL, thread_send, (void *)&args[i]);
                if (ret != 0) {
                    log_error("init threads failed");
                    exit(1);
                }
                set_thread_affinity(threads[i], i % sysconf(_SC_NPROCESSORS_ONLN));
            }

            for (size_t i = 0; i < thread_sz; i++) {
                pthread_join(threads[i], NULL);
            }

            pthread_mutex_destroy(&qp_lock);

        }
        close(peer_fd);
    }
    free(server_name);
    free(local_ip);
    free(port);
    destroy_ib_res((&local_res));
    destroy_ib_res((&remote_res));
    destroy_ib_ctx(&ctx);
    free(buffers);
    return 0;
}
