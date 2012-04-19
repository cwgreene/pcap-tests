#ifndef PCAP_ERRORS_H
#define PCAP_ERRORS_H
#include <pcap/pcap.h>

void handle_pcap_errors(pcap_t *handle, int errcode, char *msg);
void exit_error(char *msg, int errcode);
#endif
