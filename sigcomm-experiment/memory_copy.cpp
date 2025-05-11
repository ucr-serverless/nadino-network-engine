#include "http.h"

#include <chrono>
#include <iostream>
#include <cstring>
struct http_transaction scratch_pad;

int main()
{
    struct http_transaction tmp;
    size_t iter = 100000;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < 100000; i++)
    {
        memcpy(&scratch_pad, &tmp, sizeof(struct http_transaction));
        tmp.tenant_id = i;
        memcpy(&tmp, &scratch_pad, sizeof(struct http_transaction));

    }

    auto end = std::chrono::high_resolution_clock::now();
    std::cout<<"average time between " << iter << " runs is " << (end - start).count()/ iter << " ns" << std::endl;
}

