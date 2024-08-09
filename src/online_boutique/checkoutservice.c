/*
# Copyright 2022 University of California, Riverside
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

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memzone.h>

#include "http.h"
#include "io.h"
#include "spright.h"
#include "utility.h"

static int pipefd_rx[UINT8_MAX][2];
static int pipefd_tx[UINT8_MAX][2];

char defaultCurrency[5] = "CAD";

void prepareOrderItemsAndShippingQuoteFromCart(struct http_transaction *txn);

static void sendOrderConfirmation(struct http_transaction *txn)
{
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, txn->order_result.OrderId);
    strcpy(txn->order_result.ShippingTrackingId, txn->ship_order_response.TrackingId);
    txn->order_result.ShippingCost = txn->get_quote_response.CostUsd;
    txn->order_result.ShippingAddress = txn->place_order_request.address;

    strcpy(txn->email_req.Email, txn->place_order_request.Email);

    strcpy(txn->rpc_handler, "SendOrderConfirmation");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = EMAIL_SVC;
    txn->checkoutsvc_hop_cnt++;
}

static void emptyUserCart(struct http_transaction *txn)
{
    EmptyCartRequest *in = &txn->empty_cart_request;
    strcpy(in->UserId, "ucr-students");

    strcpy(txn->rpc_handler, "EmptyCart");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = CART_SVC;
    txn->checkoutsvc_hop_cnt++;
}

static void shipOrder(struct http_transaction *txn)
{
    ShipOrderRequest *in = &txn->ship_order_request;
    strcpy(in->address.StreetAddress, txn->place_order_request.address.StreetAddress);
    strcpy(in->address.City, txn->place_order_request.address.City);
    strcpy(in->address.State, txn->place_order_request.address.State);
    strcpy(in->address.Country, txn->place_order_request.address.Country);
    in->address.ZipCode = txn->place_order_request.address.ZipCode;

    strcpy(txn->rpc_handler, "ShipOrder");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = SHIPPING_SVC;
    txn->checkoutsvc_hop_cnt++;
}

static void chargeCard(struct http_transaction *txn)
{
    strcpy(txn->charge_request.CreditCard.CreditCardNumber, txn->place_order_request.CreditCard.CreditCardNumber);
    txn->charge_request.CreditCard.CreditCardCvv = txn->place_order_request.CreditCard.CreditCardCvv;
    txn->charge_request.CreditCard.CreditCardExpirationYear =
        txn->place_order_request.CreditCard.CreditCardExpirationYear;
    txn->charge_request.CreditCard.CreditCardExpirationMonth =
        txn->place_order_request.CreditCard.CreditCardExpirationMonth;

    strcpy(txn->charge_request.Amount.CurrencyCode, txn->total_price.CurrencyCode);
    txn->charge_request.Amount.Units = txn->total_price.Units;
    txn->charge_request.Amount.Nanos = txn->total_price.Nanos;

    strcpy(txn->rpc_handler, "Charge");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = PAYMENT_SVC;
    txn->checkoutsvc_hop_cnt++;
}

static void calculateTotalPrice(struct http_transaction *txn)
{
    log_info("Calculating total price...");
    int i = 0;
    for (i = 0; i < txn->orderItemViewCntr; i++)
    {
        MultiplySlow(&txn->order_item_view[i].Cost, txn->order_item_view[i].Item.Quantity);
        Sum(&txn->total_price, &txn->order_item_view[i].Cost);
    }
    log_info("\t\t>>>>>> priceItem(s) Subtotal: %ld.%d", txn->total_price.Units, txn->total_price.Nanos);
    log_info("\t\t>>>>>> Shipping & Handling: %ld.%d", txn->get_quote_response.CostUsd.Units,
             txn->get_quote_response.CostUsd.Nanos);
    Sum(&txn->total_price, &txn->get_quote_response.CostUsd);

    return;
}

static void returnResponseToFrontendWithOrderResult(struct http_transaction *txn)
{
    txn->next_fn = FRONTEND;
    txn->caller_fn = CHECKOUT_SVC;
}

static void returnResponseToFrontend(struct http_transaction *txn)
{
    txn->next_fn = FRONTEND;
    txn->caller_fn = CHECKOUT_SVC;
}

// Convert currency for a ShippingQuote
static void convertCurrencyOfShippingQuote(struct http_transaction *txn)
{
    if (strcmp(defaultCurrency, "USD") == 0)
    {
        log_info("Default Currency is USD. Skip convertCurrencyOfShippingQuote");
        txn->get_quote_response.conversion_flag = true;
        txn->checkoutsvc_hop_cnt++;
        prepareOrderItemsAndShippingQuoteFromCart(txn);
    }
    else
    {
        if (txn->get_quote_response.conversion_flag == true)
        {
            txn->get_quote_response.CostUsd = txn->currency_conversion_result;
            log_info("Write back convertCurrencyOfShippingQuote");
            txn->checkoutsvc_hop_cnt++;
            prepareOrderItemsAndShippingQuoteFromCart(txn);
        }
        else
        {
            log_info("Default Currency is %s. Do convertCurrencyOfShippingQuote", defaultCurrency);
            strcpy(txn->currency_conversion_req.ToCode, defaultCurrency);
            strcpy(txn->currency_conversion_req.From.CurrencyCode, txn->get_quote_response.CostUsd.CurrencyCode);
            txn->currency_conversion_req.From.Units = txn->get_quote_response.CostUsd.Units;
            txn->currency_conversion_req.From.Nanos = txn->get_quote_response.CostUsd.Nanos;

            strcpy(txn->rpc_handler, "Convert");
            txn->caller_fn = CHECKOUT_SVC;
            txn->next_fn = CURRENCY_SVC;

            txn->get_quote_response.conversion_flag = true;
        }
    }
    return;
}

static void quoteShipping(struct http_transaction *txn)
{
    GetQuoteRequest *in = &txn->get_quote_request;
    in->num_items = 0;
    txn->get_quote_response.conversion_flag = false;

    int i;
    for (i = 0; i < txn->get_cart_response.num_items; i++)
    {
        in->Items[i].Quantity = i + 1;
        in->num_items++;
    }

    strcpy(txn->rpc_handler, "GetQuote");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = SHIPPING_SVC;
    txn->checkoutsvc_hop_cnt++;
}

// Convert currency for products in the cart
static void convertCurrencyOfCart(struct http_transaction *txn)
{
    if (strcmp(defaultCurrency, "USD") == 0)
    {
        log_info("Default Currency is USD. Skip convertCurrencyOfCart");
        txn->checkoutsvc_hop_cnt++;
        prepareOrderItemsAndShippingQuoteFromCart(txn);
        return;
    }
    else
    {
        if (txn->orderItemCurConvertCntr != 0)
        {
            txn->order_item_view[txn->orderItemCurConvertCntr - 1].Cost = txn->currency_conversion_result;
        }

        if (txn->orderItemCurConvertCntr < txn->orderItemViewCntr)
        {
            log_info("Default Currency is %s. Do convertCurrencyOfCart", defaultCurrency);
            strcpy(txn->currency_conversion_req.ToCode, defaultCurrency);
            txn->currency_conversion_req.From = txn->order_item_view[txn->orderItemCurConvertCntr].Cost;

            strcpy(txn->rpc_handler, "Convert");
            txn->caller_fn = CHECKOUT_SVC;
            txn->next_fn = CURRENCY_SVC;

            txn->orderItemCurConvertCntr++;
            return;
        }
        else
        {
            txn->checkoutsvc_hop_cnt++;
            prepareOrderItemsAndShippingQuoteFromCart(txn);
            return;
        }
    }
}

static void getOrderItemInfo(struct http_transaction *txn)
{
    log_info("%d items in the cart.", txn->get_cart_response.num_items);
    if (txn->get_cart_response.num_items <= 0)
    {
        log_info("None items in the cart.");
        txn->total_price.Units = 0;
        txn->total_price.Nanos = 0;
        returnResponseToFrontend(txn);
        return;
    }

    if (txn->orderItemViewCntr != 0)
    {
        strcpy(txn->order_item_view[txn->orderItemViewCntr - 1].Item.ProductId, txn->get_product_response.Id);
        txn->order_item_view[txn->orderItemViewCntr - 1].Cost = txn->get_product_response.PriceUsd;
    }

    if (txn->orderItemViewCntr < txn->get_cart_response.num_items)
    {
        strcpy(txn->get_product_request.Id, txn->get_cart_response.Items[txn->orderItemViewCntr].ProductId);
        // log_info("Product ID: %s", txn->get_product_request.Id);

        strcpy(txn->rpc_handler, "GetProduct");
        txn->caller_fn = CHECKOUT_SVC;
        txn->next_fn = PRODUCTCATA_SVC;

        txn->orderItemViewCntr++;
    }
    else
    {
        txn->orderItemCurConvertCntr = 0;
        convertCurrencyOfCart(txn);
        txn->checkoutsvc_hop_cnt++;
    }
}

static void getCart(struct http_transaction *txn)
{
    strcpy(txn->get_cart_request.UserId, "ucr-students");

    strcpy(txn->rpc_handler, "GetCart");
    txn->caller_fn = CHECKOUT_SVC;
    txn->next_fn = CART_SVC;
    txn->checkoutsvc_hop_cnt++;
}

static void prepOrderItems(struct http_transaction *txn)
{

    if (txn->checkoutsvc_hop_cnt == 1)
    {
        getOrderItemInfo(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 2)
    {
        convertCurrencyOfCart(txn);
    }
    else
    {
        log_info("prepOrderItems doesn't know what to do for HOP %u.", txn->checkoutsvc_hop_cnt);
        returnResponseToFrontend(txn);
    }
}

void prepareOrderItemsAndShippingQuoteFromCart(struct http_transaction *txn)
{
    log_info("Call prepareOrderItemsAndShippingQuoteFromCart ### Hop: %u", txn->checkoutsvc_hop_cnt);

    if (txn->checkoutsvc_hop_cnt == 0)
    {
        getCart(txn);
        txn->orderItemViewCntr = 0;
    }
    else if (txn->checkoutsvc_hop_cnt >= 1 && txn->checkoutsvc_hop_cnt <= 2)
    {
        prepOrderItems(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 3)
    {
        quoteShipping(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 4)
    {
        convertCurrencyOfShippingQuote(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 5)
    {
        calculateTotalPrice(txn);
        chargeCard(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 6)
    {
        shipOrder(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 7)
    {
        emptyUserCart(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 8)
    {
        sendOrderConfirmation(txn);
    }
    else if (txn->checkoutsvc_hop_cnt == 9)
    {
        returnResponseToFrontendWithOrderResult(txn);
    }
    else
    {
        log_info("prepareOrderItemsAndShippingQuoteFromCart doesn't know what to do for HOP %u.",
                 txn->checkoutsvc_hop_cnt);
        returnResponseToFrontend(txn);
    }
}

static void PlaceOrder(struct http_transaction *txn)
{
    prepareOrderItemsAndShippingQuoteFromCart(txn);
}

static void *nf_worker(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1)
    {
        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1))
        {
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }

        // if (strcmp(txn->rpc_handler, "PlaceOrder") == 0) {
        PlaceOrder(txn);
        // } else {
        // 	log_info("%s() is not supported", txn->rpc_handler);
        // 	log_info("\t\t#### Run Mock Test ####");
        // 	// MockEmailRequest(txn);
        // 	// SendOrderConfirmation(txn);
        // }

        bytes_written = write(pipefd_tx[index][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_rx(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    uint8_t i;
    int ret;

    for (i = 0;; i = (i + 1) % cfg->nf[fn_id - 1].n_threads)
    {
        ret = io_rx((void **)&txn);
        if (unlikely(ret == -1))
        {
            log_error("io_rx() error");
            return NULL;
        }

        bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_tx(void *arg)
{
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

    for (i = 0; i < cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = set_nonblocking(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            return NULL;
        }

        event[0].events = EPOLLIN;
        event[0].data.fd = pipefd_tx[i][0];

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd_tx[i][0], &event[0]);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return NULL;
        }
    }

    while (1)
    {
        n_fds = epoll_wait(epfd, event, cfg->nf[fn_id - 1].n_threads, -1);
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

            log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, \
                Caller Fn: %s (#%u), RPC Handler: %s()",
                      txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
                      txn->caller_nf, txn->caller_fn, txn->rpc_handler);

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

/* TODO: Cleanup on errors */
static int nf(uint8_t nf_id)
{
    const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint8_t i;
    int ret;

    fn_id = nf_id;

    memzone = rte_memzone_lookup(MEMZONE_NAME);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_lookup() error");
        return -1;
    }

    cfg = memzone->addr;

    ret = io_init();
    if (unlikely(ret == -1))
    {
        log_error("io_init() error");
        return -1;
    }

    for (i = 0; i < cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pipe(pipefd_rx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }

        ret = pipe(pipefd_tx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = pthread_create(&thread_rx, NULL, &nf_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_create(&thread_tx, NULL, &nf_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    for (i = 0; i < cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }

    ret = pthread_join(thread_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(thread_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = close(pipefd_rx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_rx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    log_set_level_from_env();

    uint8_t nf_id;
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
        log_error("Network Function ID not provided");
        goto error_1;
    }

    errno = 0;
    nf_id = strtol(argv[1], NULL, 10);
    if (unlikely(errno != 0 || nf_id < 1))
    {
        log_error("Invalid value for Network Function ID");
        goto error_1;
    }

    ret = nf(nf_id);
    if (unlikely(ret == -1))
    {
        log_error("nf() error");
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
