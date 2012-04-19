#include <pcap/pcap.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pcap_errors.h"

typedef struct{
    char *device;
    char *port_str;

    int list_devices;
} Options;

typedef struct{
    u_char ethernet_hdr[14];
    u_char ip_hdr[20]; //offset
    uint16_t src_port;
    uint16_t dest_port;
    
    uint32_t seq_number;
    uint32_t ack_number;
    uint16_t flags;
    uint16_t window_size;
} TCP_header_part16;

int parse_args(int argc,char **argv, Options *options) {
    if(argc <3)
    {
        printf("usage: filter_on INTERFACE PORT\n");
        exit(0);
    }
    options->device = argv[1];
    options->port_str = argv[2];
}



void show_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    int result = pcap_findalldevs(&alldevsp, errbuf);
    if(result) {
        exit_error(errbuf, result);
    }
    pcap_if_t *cur = alldevsp;
    while(cur)
    {
        printf("Device: %s - %s\n" , cur->name, cur->description ? cur->description : "");
        cur = cur->next;
    }
}

void filter_on_port(pcap_t *handle, char *filter, char *port){
    char program_string[80];
    memset(program_string, 0, 80);
    struct bpf_program fp;
    int result;

    // Copy filter string
    strcpy(program_string, filter);
    strcat(program_string, port);

    // Compile and set
    printf("Compiling: %s\n",program_string);
    result = pcap_compile(handle, &fp, program_string, 1, PCAP_NETMASK_UNKNOWN);
    handle_pcap_errors(handle, result, "pcap_compile");

    result = pcap_setfilter(handle, &fp);
    handle_pcap_errors(handle, result, "pcap_setfilter");
}

#define ALL_PORTS (256*256)

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;

    Options options;

    parse_args(argc, argv, &options);

    if(options.list_devices) {
        show_devices();
        exit(0);
    }

    // Create Handles for in and out
    pcap_t *in_handle = pcap_create(argv[1], errbuf);
    pcap_t *out_handle = pcap_create(argv[1], errbuf);

    if(!in_handle | !out_handle )
        exit_error(errbuf, -1);
    
    int result = 0;

    // Set timeout
    result = pcap_set_timeout(in_handle, 1); // Header size up to window size
    result = pcap_set_timeout(out_handle, 1); // Header size up to window size
    handle_pcap_errors(in_handle, result, "set_timeout");
    handle_pcap_errors(out_handle, result, "set_timeout");



    // Activate!
    result = pcap_activate(out_handle);
    result = pcap_activate(in_handle);
    handle_pcap_errors(out_handle, result, "pcap_activate");
    handle_pcap_errors(in_handle, result, "pcap_activate");
    // Set Filter
    filter_on_port(out_handle, "src port ", options.port_str);
    filter_on_port(in_handle, "dst port ", options.port_str);


    // Count packet lenghts on port
    int out_byte_count = 0;
    int in_byte_count = 0;

    for(int i = 0; i < 100; i++) {
        pcap_next_ex(out_handle, &pkthdr, &pkt_data);
        out_byte_count += pkthdr->len;

        pcap_next_ex(in_handle, &pkthdr, &pkt_data);
        in_byte_count += pkthdr->len;
    }

    printf("In Bytes: %d\n", in_byte_count);
    printf("Out Bytes: %d\n", out_byte_count);

    return 0;
}
