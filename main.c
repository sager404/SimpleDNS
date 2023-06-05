#include "dns.h"
#include "root.h"
#include "server.h"

int main() {
    unsigned char ip[] = "www.name.com";
    struct DNS_RR rr;
    memset(&rr, 0, sizeof(rr));
    struct DNS_RR *rrs = get_root_data();
    return 0;
}