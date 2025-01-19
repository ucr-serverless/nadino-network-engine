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

#include "utility.h"
#include "RDMA_utils.h"
#include "spright.h"
#include <stdint.h>

void save_mempool_element_address(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx)
{
    void **addr_list = (void **)opaque;
    addr_list[idx] = obj;
}

void retrieve_mempool_addresses(struct rte_mempool *mp, void **addr_list)
{
    rte_mempool_obj_iter(mp, save_mempool_element_address, addr_list);
}

int compare_addr(void *left, void *right)
{

    uint64_t left_op = *(uint64_t *)left;
    uint64_t right_op = *(uint64_t *)right;
    if (left_op < right_op)
    {
        return -1;
    }
    else if (left_op > right_op)
    {
        return 1;
    }
    else
    {
        return 0;
    }
    return 0;
}

void set_node(uint8_t fn_id, uint8_t node_idx)
{
    cfg->inter_node_rt[fn_id] = node_idx;
}

uint8_t get_node(uint8_t fn_id)
{
    uint8_t peer_node_idx = cfg->inter_node_rt[fn_id];

    log_debug("Destination function is %u on node %u (%s:%u).", fn_id, peer_node_idx,
              cfg->nodes[peer_node_idx].ip_address, INTERNAL_SERVER_PORT);

    return peer_node_idx;
}

void delete_node(uint8_t fn_id)
{
    cfg->inter_node_rt[fn_id] = 0;
}

void print_ip_address(struct in_addr *ip)
{
    log_info("%s", inet_ntoa(*ip));
}

void print_rt_table()
{
    printf("Inter-node Routing Table\n");
    for (int i = 1; i <= cfg->n_nfs; i++)
    {
        printf("\tFn: %d, Node: %d\n", i, cfg->inter_node_rt[i]);
    }
}

void PrintAdResponse(struct http_transaction *in)
{
    int i;
    log_info("Ads in AdResponse:");
    for (i = 0; i < in->ad_response.num_ads; i++)
    {
        log_info("Ad[%d] RedirectUrl: %s\tText: %s", i + 1, in->ad_response.Ads[i].RedirectUrl,
                 in->ad_response.Ads[i].Text);
    }
    printf("\n");
}

void PrintSupportedCurrencies(struct http_transaction *in)
{
    log_info("Supported Currencies: ");
    int i = 0;
    for (i = 0; i < in->get_supported_currencies_response.num_currencies; i++)
    {
        log_info("%d. %s\t", i + 1, in->get_supported_currencies_response.CurrencyCodes[i]);
    }
    printf("\n");
}

void PrintProduct(Product *p)
{
    log_info("Product Name: %s\t ID: %s", p->Name, p->Id);
    log_info("Product Description: %s", p->Description);
    log_info("Product Picture: %s", p->Picture);
    log_info("Product Price: %s %ld.%d", p->PriceUsd.CurrencyCode, p->PriceUsd.Units, p->PriceUsd.Nanos);
    log_info("Product Categories: ");

    int i = 0;
    for (i = 0; i < p->num_categories; i++)
    {
        log_info("%d. %s\t", i + 1, p->Categories[i]);
    }
    printf("\n");
}

void PrintListProductsResponse(struct http_transaction *txn)
{
    log_info("### PrintListProductsResponse ###");
    ListProductsResponse *out = &txn->list_products_response;
    int size = sizeof(out->Products) / sizeof(out->Products[0]);
    int i = 0;
    for (i = 0; i < size; i++)
    {
        PrintProduct(&out->Products[i]);
    }
    return;
}

void PrintGetProductResponse(struct http_transaction *txn)
{
    log_info("### PrintGetProductResponse ###");
    PrintProduct(&txn->get_product_response);
}

void PrintSearchProductsResponse(struct http_transaction *txn)
{
    log_info("### PrintSearchProductsResponse ###");
    SearchProductsResponse *out = &txn->search_products_response;
    int i;
    for (i = 0; i < out->num_products; i++)
    {
        PrintProduct(&out->Results[i]);
    }
    return;
}

void PrintGetCartResponse(struct http_transaction *txn)
{
    log_info("\t\t#### PrintGetCartResponse ####");
    Cart *out = &txn->get_cart_response;
    log_info("Cart for user %s: ", out->UserId);

    if (txn->get_cart_response.num_items == -1)
    {
        log_info("EMPTY CART!");
        return;
    }

    int i;
    for (i = 0; i < out->num_items; i++)
    {
        log_info("\t%d. ProductId: %s \tQuantity: %d", i + 1, out->Items[i].ProductId, out->Items[i].Quantity);
    }
    printf("\n");
    return;
}

void PrintConversionResult(struct http_transaction *in)
{
    log_info("Conversion result: ");
    log_info("CurrencyCode: %s\t", in->currency_conversion_result.CurrencyCode);
    log_info("Value: %ld.%d", in->currency_conversion_result.Units, in->currency_conversion_result.Nanos);
}

void printMoney(Money *money)
{
    printf("Money:\n");
    printf("  Currency Code: %s\n", money->CurrencyCode);
    printf("  Units: %ld\n", money->Units);
    printf("  Nanos: %d\n", money->Nanos);
}

void printCurrencyConversionRequest(CurrencyConversionRequest *request)
{
    printf("Currency Conversion Request:\n");
    printMoney(&request->From);
    printf("  To Currency Code: %s\n", request->ToCode);
}

void MockCurrencyConversionRequest(struct http_transaction *in)
{
    strcpy(in->currency_conversion_req.ToCode, "USD");
    strcpy(in->currency_conversion_req.From.CurrencyCode, "EUR");

    in->currency_conversion_req.From.Units = 300;
    in->currency_conversion_req.From.Nanos = 0;
}

void PrintProductView(struct http_transaction *txn)
{
    log_info("\t\t#### ProductView ####");

    // int size = sizeof(txn->product_view)/sizeof(txn->product_view[0]);
    int size = txn->productViewCntr;
    int i = 0;
    for (i = 0; i < size; i++)
    {
        Product *p = &txn->product_view[i].Item;
        Money *m = &txn->product_view[i].Price;
        log_info("Product Name: %s\t ID: %s", p->Name, p->Id);
        log_info("Product %s Price:  %ld.%d", p->PriceUsd.CurrencyCode, p->PriceUsd.Units, p->PriceUsd.Nanos);
        log_info("Product %s Price:  %ld.%d", m->CurrencyCode, m->Units, m->Nanos);
    }
}

void PrintListRecommendationsResponse(struct http_transaction *txn)
{
    log_info("Recommended Product ID: %s", txn->list_recommendations_response.ProductId);
}

void PrintShipOrderResponse(struct http_transaction *txn)
{
    ShipOrderResponse *out = &txn->ship_order_response;
    log_info("Tracking ID: %s", out->TrackingId);
}

void PrintGetQuoteResponse(struct http_transaction *txn)
{
    GetQuoteResponse *out = &txn->get_quote_response;
    log_info("Shipping cost: %s %ld.%d", out->CostUsd.CurrencyCode, out->CostUsd.Units, out->CostUsd.Nanos);
}

void PrintTotalPrice(struct http_transaction *txn)
{
    log_info("Total Price:  %ld.%d", txn->total_price.Units, txn->total_price.Nanos);
}

void Sum(Money *total, Money *add)
{

    total->Units = total->Units + add->Units;
    total->Nanos = total->Nanos + add->Nanos;

    if ((total->Units == 0 && total->Nanos == 0) || (total->Units > 0 && total->Nanos >= 0) ||
        (total->Units < 0 && total->Nanos <= 0))
    {
        // same sign <units, nanos>
        total->Units += (int64_t)(total->Nanos / NANOSMOD);
        total->Nanos = total->Nanos % NANOSMOD;
    }
    else
    {
        // different sign. nanos guaranteed to not to go over the limit
        if (total->Units > 0)
        {
            total->Units--;
            total->Nanos += NANOSMOD;
        }
        else
        {
            total->Units++;
            total->Nanos -= NANOSMOD;
        }
    }

    return;
}

void MultiplySlow(Money *total, uint32_t n)
{
    for (; n > 1;)
    {
        Sum(total, total);
        n--;
    }
    return;
}

void PrintPlaceOrderRequest(struct http_transaction *txn)
{
    log_info("email: %s", txn->place_order_request.Email);
    log_info("street_address: %s", txn->place_order_request.address.StreetAddress);
    log_info("zip_code: %d", txn->place_order_request.address.ZipCode);
    log_info("city: %s", txn->place_order_request.address.City);
    ;
    log_info("state: %s", txn->place_order_request.address.State);
    log_info("country: %s", txn->place_order_request.address.Country);
    log_info("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);
    log_info("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);
    log_info("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);
    log_info("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);
}

void parsePlaceOrderRequest(struct http_transaction *txn)
{
    char *query = httpQueryParser(txn->request);
    // log_info("QUERY: %s", query);

    char *start_of_query = strtok(query, "&");
    // char *email = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.Email, strchr(start_of_query, '=') + 1);
    // log_info("email: %s", txn->place_order_request.Email);

    start_of_query = strtok(NULL, "&");
    // char *street_address = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.address.StreetAddress, strchr(start_of_query, '=') + 1);
    // log_info("street_address: %s", txn->place_order_request.address.StreetAddress);

    start_of_query = strtok(NULL, "&");
    // char *zip_code = strchr(start_of_query, '=') + 1;
    txn->place_order_request.address.ZipCode = atoi(strchr(start_of_query, '=') + 1);
    // log_info("zip_code: %d", txn->place_order_request.address.ZipCode);

    start_of_query = strtok(NULL, "&");
    // char *city = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.address.City, strchr(start_of_query, '=') + 1);
    // log_info("city: %s", txn->place_order_request.address.City);

    start_of_query = strtok(NULL, "&");
    // char *state = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.address.State, strchr(start_of_query, '=') + 1);
    // log_info("state: %s", txn->place_order_request.address.State);

    start_of_query = strtok(NULL, "&");
    // char *country = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.address.Country, strchr(start_of_query, '=') + 1);
    // log_info("country: %s", txn->place_order_request.address.Country);

    start_of_query = strtok(NULL, "&");
    // char *credit_card_number = strchr(start_of_query, '=') + 1;
    strcpy(txn->place_order_request.CreditCard.CreditCardNumber, strchr(start_of_query, '=') + 1);
    // log_info("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);

    start_of_query = strtok(NULL, "&");
    // char *credit_card_expiration_month = strchr(start_of_query, '=') + 1;
    txn->place_order_request.CreditCard.CreditCardExpirationMonth = atoi(strchr(start_of_query, '=') + 1);
    // log_info("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);

    start_of_query = strtok(NULL, "&");
    // char *credit_card_expiration_year = strchr(start_of_query, '=') + 1;
    txn->place_order_request.CreditCard.CreditCardExpirationYear = atoi(strchr(start_of_query, '=') + 1);
    // log_info("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);

    start_of_query = strtok(NULL, "&");
    // char *credit_card_cvv = strchr(start_of_query, '=') + 1;
    txn->place_order_request.CreditCard.CreditCardCvv = atoi(strchr(start_of_query, '=') + 1);
    // log_info("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);
}

char *httpQueryParser(char *req)
{
    char tmp[600];
    strcpy(tmp, req);

    char *start_of_path = strtok(tmp, " ");
    start_of_path = strtok(NULL, " ");
    char *start_of_query = strchr(start_of_path, '?') + 1;

    // Remove trailing slash if present
    size_t len = strlen(start_of_query);
    if (start_of_query[len - 1] == '/')
    {
        start_of_query[len - 1] = '\0';
    }

    return start_of_query;
}

void cfg_print(struct spright_cfg_s *cfg)
{
    uint8_t i;
    uint8_t j;

    printf("Name: %s\n", cfg->name);

    printf("Number of Tenants: %d\n", cfg->n_tenants);
    printf("Tenants:\n");
    for (i = 0; i < cfg->n_tenants; i++)
    {
        printf("\tID: %hhu\n", cfg->tenants[i].id);
        printf("\tWeight: %d\n", cfg->tenants[i].weight);
        printf("\n");
        if (cfg->tenants[i].n_routes > 0)
        {
            printf("\troutes = [");
            for (j = 0; j < cfg->tenants[i].n_routes; j++)
            {
                printf("%hhu ", cfg->tenants[i].routes[j]);
            }
            printf("\b]\n");
        }
        printf("\n");
    }

    printf("Number of NFs: %hhu\n", cfg->n_nfs);
    printf("NFs:\n");
    for (i = 0; i < cfg->n_nfs; i++)
    {
        printf("\tID: %hhu\n", cfg->nf[i].fn_id);
        printf("\ttenant_id: %hhu\n", cfg->nf[i].tenant_id);

        printf("\tName: %s\n", cfg->nf[i].name);
        printf("\tNumber of Threads: %hhu\n", cfg->nf[i].n_threads);
        printf("\tParams:\n");
        printf("\t\tmemory_mb: %hhu\n", cfg->nf[i].param.memory_mb);
        printf("\t\tsleep_ns: %u\n", cfg->nf[i].param.sleep_ns);
        printf("\t\tcompute: %u\n", cfg->nf[i].param.compute);
        printf("\tNode: %u\n", cfg->nf[i].node);
        printf("\n");
    }

    printf("Number of Routes: %hhu\n", cfg->n_routes);
    printf("Routes:\n");
    for (i = 0; i < cfg->n_routes; i++)
    {
        printf("\tID: %hhu\n", cfg->route[i].id);
        printf("\tName: %s\n", cfg->route[i].name);
        printf("\tLength = %hhu\n", cfg->route[i].length);
        if (cfg->route[i].length > 0)
        {
            printf("\tHops = [");
            for (j = 0; j < cfg->route[i].length; j++)
            {
                printf("%hhu ", cfg->route[i].hop[j]);
            }
            printf("\b]\n");
        }
        printf("\n");
    }

    printf("Number of Nodes: %hhu\n", cfg->n_nodes);
    printf("Local Node Index: %u\n", cfg->local_node_idx);
    printf("Nodes:\n");
    for (i = 0; i < cfg->n_nodes; i++)
    {
        printf("\tID: %hhu\n", i);
        printf("\tHostname: %s\n", cfg->nodes[i].hostname);
        printf("\tIP Address: %s\n", cfg->nodes[i].ip_address);
        printf("\tPort = %u\n", cfg->nodes[i].port);
        printf("\tRDMA_device%s\n", cfg->nodes[i].rdma_device);
        printf("\tcomch_server_dev = %s\n", cfg->nodes[i].comch_server_device);
        printf("\tcomch_client_dev = %s\n", cfg->nodes[i].comch_client_device);
        printf("\tsgid_idx = %u\n", cfg->nodes[i].sgid_idx);
        printf("\n");
    }

    printf("memory_manager:\n");
    printf("\tMM_Port = %u\n", cfg->memory_manager.port);
    printf("\tis_remote_memory = %u\n", cfg->memory_manager.is_remote_memory);

    printf("RDMA:\n");
    printf("\tuse RDMA: %d \n", cfg->use_rdma);
    printf("\tuse one_side: %d \n", cfg->use_one_side);

    print_rt_table();
    printf("Local mempool size: %u\n", cfg->local_mempool_size);
    printf("Local mempool elt size: %u\n", cfg->local_mempool_elt_size);
    printf("rdma_n_init_task: %u\n", cfg->rdma_n_init_task);
    printf("rdma_n_init_recv_req: %u\n", cfg->rdma_n_init_recv_req);
}
int cfg_init(char *cfg_file, struct spright_cfg_s *cfg)
{
    config_setting_t *subsubsetting = NULL;
    config_setting_t *subsetting = NULL;
    config_setting_t *setting = NULL;
    const char *name = NULL;
    const char *hostname = NULL;
    const char *ip_address = NULL;
    const char *device_name = NULL;
    config_t config;
    int value;
    int ret;
    int id;
    int n;
    int m;
    int i;
    int j;
    int node;
    int port;
    int weight;
    int is_hostname_matched = -1;

    log_debug("size of http_transaction: %lu\n", sizeof(struct http_transaction));

    config_init(&config);

    ret = config_read_file(&config, cfg_file);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("config_read_file() error: line %d: %s", config_error_line(&config), config_error_text(&config));
        goto error;
    }

    ret = config_lookup_string(&config, "name", &name);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    strcpy(cfg->name, name);

    setting = config_lookup(&config, "nfs");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    // =========NF==========
    n = config_setting_length(setting);
    cfg->n_nfs = n;

    for (i = 0; i < cfg->n_nfs; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }
        cfg->nf[i].fn_id = id;

        ret = config_setting_lookup_int(subsetting, "tenant_id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }
        cfg->nf[i].tenant_id = id;
        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        strcpy(cfg->nf[i].name, name);

        ret = config_setting_lookup_int(subsetting, "n_threads", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[i].n_threads = value;

        subsubsetting = config_setting_lookup(subsetting, "params");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsubsetting, "memory_mb", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[i].param.memory_mb = value;

        ret = config_setting_lookup_int(subsubsetting, "sleep_ns", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[i].param.sleep_ns = value;

        ret = config_setting_lookup_int(subsubsetting, "compute", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[i].param.compute = value;

        ret = config_setting_lookup_int(subsetting, "node", &node);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_info("Set default node as 0.");
            node = 0;
        }

        cfg->nf[i].node = node;
        set_node(id, node);
    }

    // =========rotes==========
    setting = config_lookup(&config, "routes");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_routes = n + 1;

    // the default route occupies a position
    strcpy(cfg->route[0].name, "Default");
    cfg->route[0].length = 0;

    // route start from 1
    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }
        else if (unlikely(id == 0))
        {
            /* TODO: Error message */
            goto error;
        }
        cfg->route[i + 1].id = id;

        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        strcpy(cfg->route[id].name, name);

        subsubsetting = config_setting_lookup(subsetting, "hops");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_array(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        m = config_setting_length(subsubsetting);
        cfg->route[id].length = m;

        for (j = 0; j < m; j++)
        {
            value = config_setting_get_int_elem(subsubsetting, j);
            cfg->route[id].hop[j] = value;
        }
    }

    char local_hostname[HOST_NAME_MAX];
    if (gethostname(local_hostname, sizeof(local_hostname)) == -1)
    {
        log_error("gethostname() failed");
        goto error;
    }

    setting = config_lookup(&config, "nodes");
    if (unlikely(setting == NULL))
    {
        log_warn("Nodes configuration is missing.");
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_warn("Nodes configuration is missing.");
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_nodes = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_warn("Node configuration is missing.");
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node configuration is missing.");
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ID is missing.");
            goto error;
        }

        ret = config_setting_lookup_string(subsetting, "hostname", &hostname);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node hostname is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].hostname, hostname);

        /* Compare the hostnames */
        if (strcmp(local_hostname, cfg->nodes[id].hostname) == 0)
        {
            cfg->local_node_idx = i;
            is_hostname_matched = 1;
            log_info("Hostnames match: %s, node index: %u", local_hostname, i);
        }
        else
        {
            log_debug("Hostnames do not match. Got: %s, Expected: %s", local_hostname, hostname);
        }

        ret = config_setting_lookup_string(subsetting, "ip_address", &ip_address);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].ip_address, ip_address);

        ret = config_setting_lookup_int(subsetting, "port", &port);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node port is missing.");
            goto error;
        }

        cfg->nodes[id].port = port;

        ret = config_setting_lookup_string(subsetting, "rdma_device", &device_name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].rdma_device, device_name);

        ret = config_setting_lookup_string(subsetting, "comch_server_device", &device_name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].comch_server_device, device_name);
        ret = config_setting_lookup_string(subsetting, "comch_client_device", &device_name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].comch_client_device, device_name);

        ret = config_setting_lookup_int(subsetting, "sgid_idx", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("RDMA sgid_idx is missing.");
            goto error;
        }

        cfg->nodes[id].sgid_idx = value;

    }

    setting = config_lookup(&config, "tenants");
    if (unlikely(setting == NULL))
    {
        log_error("Tenants configuration is required.");
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("Tenants configuration is required.");
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_tenants = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's ID is required.", i);
            goto error;
        }

        cfg->tenants[i].id = id;

        ret = config_setting_lookup_int(subsetting, "weight", &weight);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's weight is required.", i);
            goto error;
        }

        cfg->tenants[i].weight = weight;

        subsubsetting = config_setting_lookup(subsetting, "routes");
        if (unlikely(subsubsetting == NULL))
        {
            goto error;
        }

        ret = config_setting_is_array(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            goto error;
        }

        m = config_setting_length(subsubsetting);
        cfg->tenants[i].n_routes = m;

        for (j = 0; j < m; j++)
        {
            value = config_setting_get_int_elem(subsubsetting, j);
            cfg->tenants[i].routes[j] = value;
        }
    }

    if (is_hostname_matched == -1)
    {
        log_error("No matched hostname in %s", cfg_file);
        goto error;
    }

    setting = config_lookup(&config, "memory_manager");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }
    ret = config_setting_is_group(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_lookup_int(setting, "port", &port);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_warn("Node port is missing.");
        goto error;
    }

    cfg->memory_manager.port = port;

    ret = config_setting_lookup_int(setting, "is_remote_memory", &port);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_warn("Node port is missing.");
        goto error;
    }

    cfg->memory_manager.is_remote_memory = port;

    ret = config_setting_lookup_int(setting, "local_mempool_size", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma local_mempool_size setting is required.");
        goto error;
    }

    cfg->local_mempool_size = (uint32_t)value;

    cfg->local_mempool_elt_size = sizeof(struct http_transaction);

    setting = config_lookup(&config, "rdma_settings");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_group(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_lookup_int(setting, "use_rdma", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("use_rdma setting is required.");
        goto error;
    }

    cfg->use_rdma = value;

    ret = config_setting_lookup_int(setting, "use_one_side", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("use_one_side setting is required.");
        goto error;
    }

    cfg->use_one_side = value;


    ret = config_setting_lookup_int(setting, "n_init_task", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma mr_per_qp setting is required.");
        goto error;
    }

    cfg->rdma_n_init_task = (uint32_t)value;

    // TDOO: change this settign to be optional
    ret = config_setting_lookup_int(setting, "n_init_recv_req", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma init_cqe_num setting is required.");
    }

    cfg->rdma_n_init_recv_req = (uint32_t)value;





    config_destroy(&config);
    cfg_print(cfg);
    log_debug("cfg initialize finished\n");

    return 0;

error:
    config_destroy(&config);
    return -1;
}
