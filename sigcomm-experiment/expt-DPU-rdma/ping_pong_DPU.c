#include "doca_buf.h"
#define _GNU_SOURCE
#include "dma_copy_core.h"
#include "doca_error.h"
#include "doca_log.h"
#include "doca_rdma_bridge.h"
#include "doca_buf_inventory.h"
#include "ping_pong_DPU.h"

DOCA_LOG_REGISTER(DMA_COPY_CORE);
#define MR_SIZE 10240

int rdma_cpy(struct dma_copy_cfg *dma_cfg)
{
    struct ib_ctx ctx;


    char *port = "10000";

    struct rdma_param rparams = {
        .device_idx = dma_cfg->device_idx,
        .sgid_idx = dma_cfg->sgid_idx,
        .ib_port = dma_cfg->ib_port,
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

    struct doca_dev* dev = NULL;

	struct doca_buf *remote_doca_buf = NULL;
    doca_error_t result;
    result = doca_rdma_bridge_open_dev_from_pd(ctx.pd, &dev);
    if (result != DOCA_SUCCESS) {
        log_error("open bridge fail");
    }


	struct doca_mmap *remote_mmap = NULL;
	result = doca_mmap_create_from_export(NULL,
					      (const void *)dma_cfg->exported_mmap,
					      dma_cfg->exported_mmap_len,
					      dev,
					      &remote_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create memory map from export: %s", doca_error_get_descr(result));
	}

    struct doca_buf_inventory *buf_inv = NULL;

    result = doca_buf_inventory_create(1, &buf_inv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create buffer inventory: %s", doca_error_get_descr(result));
    }

    result = doca_buf_inventory_start(buf_inv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_error_get_descr(result));
    }
	result = doca_buf_inventory_buf_get_by_addr(buf_inv,
						    remote_mmap,
						    dma_cfg->host_addr,
						    dma_cfg->host_bf_sz,
						    &remote_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA remote buffer: %s", doca_error_get_descr(result));
	}

    uint32_t lkey;
    result = doca_rdma_bridge_get_buf_mkey(remote_doca_buf, dev, &lkey);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to get DOCA buffer key: %s", doca_error_get_descr(result));
	}
    else {
        DOCA_LOG_INFO("The doca lkey is: %u", lkey);
    }
    void *data;
    result = doca_buf_get_data(remote_doca_buf, &data); 
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("get data buffer fail");
    }
    else {
        DOCA_LOG_INFO("data buf: %p, original remote addr: %p", data, (void *)dma_cfg->host_addr);
    }

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
    bool is_server = true;
    char *server_name = "";
    if (is_server)
    {

        self_fd = sock_utils_bind("0.0.0.0", port);
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
        if (wc.status != IBV_WC_SUCCESS) {
            log_error("wc status is not success");
            exit(1);
        }
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
        if (wc.status != IBV_WC_SUCCESS) {
            log_error("wc status is not success");
            exit(1);
        }
        printf("Got send cqe!!\n");

        close(peer_fd);
    }
    destroy_ib_res((&local_res));
    destroy_ib_res((&remote_res));
    destroy_ib_ctx(&ctx);
    free(buf);
    free(buffers);
    return 0;
}
