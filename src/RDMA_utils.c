
#include "RDMA_utils.h"
#include "log.h"
#include "sock_utils.h"
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#define FIND_SLOT_RETRY_MAX 3

int init_qp_bitmap(uint32_t mr_num, uint32_t single_mr_size, uint32_t slot_size, bitmap **bp)
{
    assert(single_mr_size % slot_size == 0);
    *bp = bitmap_allocate(mr_num * single_mr_size / slot_size);
    if (!bp)
    {
        log_error("Error, allocate bitmap\n");
        exit(1);
    }
    return RDMA_SUCCESS;
}

int find_avaliable_slot_inside_mr(bitmap *bp, uint32_t mr_bp_idx_start, uint32_t mr_blk_len, uint32_t msg_blk_len,
                                  uint32_t *slot_idx)
{
    if (mr_blk_len < msg_blk_len)
    {
        log_error("Error, meg size is larger than mr size\n");
        return RDMA_FAILURE;
    }
    bool success = true;
    for (size_t i = 0; i <= mr_blk_len - msg_blk_len; i++)
    {
        for (size_t j = 0; j < msg_blk_len; j++)
        {
            if (bitmap_read(bp, mr_bp_idx_start + i + j) == 1)
            {
                i = i + j;
                success = false;
                break;
            }
        }
        if (success)
        {
            *slot_idx = mr_bp_idx_start + i;
            return RDMA_SUCCESS;
        }
        success = true;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot_try(bitmap *bp, uint32_t message_size, uint32_t slot_size, struct mr_info *start,
                            uint32_t mr_info_len, uint32_t *slot_idx, uint32_t *slot_num, void **raddr, uint32_t *rkey)
{
    assert(mr_info_len > 0);
    assert(start);
    uint32_t result_slot_idx = 0;
    uint32_t bp_idx_start_per_mr = 0;
    uint32_t msg_blk_len = memory_len_to_slot_len(message_size, slot_size);
    int ret = 0;
    for (size_t i = 0; i < mr_info_len; i++)
    {
        size_t mr_blk_len = start[i].length / slot_size;
        assert(start[i].length % slot_size == 0);

        ret = find_avaliable_slot_inside_mr(bp, bp_idx_start_per_mr, mr_blk_len, msg_blk_len, &result_slot_idx);
        if (ret == RDMA_SUCCESS)
        {
            *slot_idx = result_slot_idx;
            *slot_num = msg_blk_len;
            *rkey = start[i].rkey;
            *raddr = (unsigned char *)start[i].addr + slot_size * (result_slot_idx - bp_idx_start_per_mr);
            return RDMA_SUCCESS;
        }
        bp_idx_start_per_mr += mr_blk_len;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot(bitmap *bp, uint32_t message_size, uint32_t slot_size, struct mr_info *start,
                        uint32_t mr_info_len, uint32_t *slot_idx, uint32_t *slot_num, void **raddr, uint32_t *rkey)
{
    int ret = 0;
    for (size_t i = 0; i < FIND_SLOT_RETRY_MAX; i++)
    {
        ret = find_avaliable_slot_try(bp, message_size, slot_size, start, mr_info_len, slot_idx, slot_num, raddr, rkey);
        if (ret == RDMA_SUCCESS)
        {
            return RDMA_SUCCESS;
        }
    }
    log_error("Error, can not find avaliable slot in %d retries\n", FIND_SLOT_RETRY_MAX);
    exit(1);
}

int remote_slot_idx_convert(uint32_t slot_idx, struct mr_info *start, uint32_t mr_info_len, uint32_t blk_size,
                            void **addr, uint32_t *rkey)
{
    assert(mr_info_len > 0);
    assert(start);
    uint32_t blk_len_per_mr = 0;
    size_t i = 0;
    for (; i < mr_info_len; i++)
    {
        blk_len_per_mr = start[i].length / blk_size;
        assert(blk_len_per_mr != 0);
        if (slot_idx >= blk_len_per_mr)
        {
            slot_idx -= blk_len_per_mr;
            continue;
        }
        else
        {
            break;
        }
    }
    if (i == mr_info_len)
    {
        return RDMA_FAILURE;
    }
    *addr = start[i].addr + blk_size * slot_idx;
    *rkey = start[i].rkey;
    return RDMA_SUCCESS;
}

int remote_addr_convert_slot_idx(void *remote_addr, uint32_t remote_len, struct mr_info *start, uint32_t mr_info_len,
                                 uint32_t slot_size, uint32_t *slot_idx, uint32_t *slot_num)
{
    uint32_t result = 0;
    for (size_t i = 0; i < mr_info_len; i++)
    {
        if ((unsigned char *)start[i].addr <= (unsigned char *)remote_addr &&
            (unsigned char *)remote_addr < (unsigned char *)start[i].addr + start[i].length)
        {
            if ((unsigned char *)remote_addr + remote_len <= (unsigned char *)start[i].addr + start[i].length)
            {
                uint32_t slot_diff = (unsigned char *)remote_addr - (unsigned char *)start[i].addr;
                if (slot_diff % slot_size != 0)
                {
                    return RDMA_FAILURE;
                }
                result += slot_diff / slot_size;
                *slot_idx = result;
                *slot_num = memory_len_to_slot_len(remote_len, slot_size);
                return RDMA_SUCCESS;
            }
        }
        result += start[i].length / slot_size;
    }
    return RDMA_FAILURE;
}

int qp_num_to_idx(struct ib_res *res, uint32_t qp_num, uint32_t *idx)
{
    size_t i = 0;
    for (; i < res->qp_num; i++)
    {
        if (res->qp_nums[i] == qp_num)
        {
            *idx = i;
            return RDMA_SUCCESS;
        }
    }
    log_error("Error, can not find qp_num %d", qp_num);
    return RDMA_FAILURE;
}

int local_slot_idx_convert(struct ib_res *local_res, uint32_t local_qp_num, uint32_t slot_idx, uint32_t mr_info_num,
                           uint32_t blk_size, void **addr)
{
    uint32_t idx = 0;
    if (qp_num_to_idx(local_res, local_qp_num, &idx) != RDMA_SUCCESS)
    {
        return RDMA_FAILURE;
    }
    struct mr_info *start = local_res->mrs + idx;
    uint32_t blk_len_per_mr = 0;

    size_t i = 0;
    for (; i < mr_info_num; i++)
    {
        blk_len_per_mr = start[i].length / blk_size;
        assert(blk_len_per_mr != 0);
        if (slot_idx >= blk_len_per_mr)
        {
            slot_idx -= blk_len_per_mr;
            continue;
        }
        else
        {
            break;
        }
    }
    if (i == mr_info_num)
    {
        return RDMA_FAILURE;
    }
    *addr = start[i].addr + blk_size * slot_idx;
    return RDMA_SUCCESS;
}

uint32_t memory_len_to_slot_len(uint32_t len, uint32_t slot_size)
{
    assert(len > 0);
    assert(slot_size > 0);
    return (len + slot_size - 1) / slot_size;
}

int send_release_signal(int sock_fd, void *addr, uint32_t len)
{
    if (sock_utils_write(sock_fd, &addr, sizeof(void *)) != sizeof(void *))
    {
        log_error("Error, send addr\n");
        goto error;
    }
    if (sock_utils_write(sock_fd, &len, sizeof(uint32_t)) != sizeof(uint32_t))
    {
        log_error("Error, send len\n");
        goto error;
    }

    return RDMA_SUCCESS;
error:
    log_error("send_release_signal failed\n");
    return RDMA_FAILURE;
}

int receive_release_signal(int sock_fd, void **addr, uint32_t *len)
{
    if (sock_utils_read(sock_fd, addr, sizeof(void *)) != sizeof(void *))
    {
        log_error("Error, recv addr\n");
        goto error;
    }
    if (sock_utils_read(sock_fd, len, sizeof(uint32_t)) != sizeof(uint32_t))
    {
        log_error("Error, recv len\n");
        goto error;
    }

    return RDMA_SUCCESS;
error:
    log_error("recv_release_signal failed\n");
    return RDMA_FAILURE;
}
