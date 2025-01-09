#ifndef PPD_
#define PPD_

#include "doca_dev.h"
#include "doca_error.h"
#include "doca_types.h"
#include "ib.h"
#include "log.h"
#include "qp.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <doca_mmap.h>
#include <doca_rdma_bridge.h>
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

int rdma_cpy(struct dma_copy_cfg *dma_cfg, struct doca_buf *remote_buf);

#endif /*ping_pong_DPU.h*/
