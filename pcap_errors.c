#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define RED(x) printf("\x1b[31m"); fflush(stdout); x; fflush(stdout); printf("\x1b[0m"); fflush(stdout);

void handle_pcap_errors(pcap_t *handle, int errcode, char *msg) {
    char *warning_prefix = "pcap warn";
    char *error_prefix = "pcap error";

    if(errcode == 0)
        return; // All clear!
    printf("%s\n",msg);

    // Warning
    if(errcode == PCAP_WARNING ||
       errcode == PCAP_WARNING_PROMISC_NOTSUP) {
        pcap_perror(handle, warning_prefix);
        return;
    }
    // Full fledge error, exit
    RED(pcap_perror(handle, error_prefix));
    exit(errcode);
}

void exit_error(char *msg, int errcode) {
    RED(printf("%s:%d\n", msg, errcode));
    exit(errcode);
}
