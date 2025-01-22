#include "palladium_nf_common.h"
#include "palladium_doca_common.h"

using namespace std;

void nf_ctx::print_nf_ctx() {
    gateway_ctx::print_gateway_ctx();

    cout << endl;
    cout<< "nf_id: " << this->nf_id << endl;

}
