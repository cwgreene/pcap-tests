#include <pcap/pcap.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pcap_errors.h"

typedef struct{
    char *device;

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
    if(argc <2)
    {
        printf("Please provide capture interface\n");
        exit(0);
    }
    options->device = argv[1];
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

    // Create Handle
    pcap_t *handle = pcap_create(argv[1], errbuf);

    if(!handle) {
        exit_error(errbuf, -1);
    }else{
        printf("Handle acquired for %s at %p\n", argv[1], handle);
    }
    
    int result = 0;

    //Set timeout
    result = pcap_set_timeout(handle, 1); // Header size up to window size
    handle_pcap_errors(handle, result, "set_timeout");

    // Set capture length
    result = pcap_set_snaplen(handle, sizeof(TCP_header_part16)); // Header size up to window size
    handle_pcap_errors(handle, result, "set_snaplen");

    // Activate!
    result = pcap_activate(handle);
    handle_pcap_errors(handle, result, "pcap_activate");

    int ports[ALL_PORTS]; // ALL the ports!
    memset(ports, 0, ALL_PORTS*sizeof(int));
    for(int i = 0; i < 100; i++) {
        //printf("Capturing!\n");
        TCP_header_part16 *hdr;
        pcap_next_ex(handle, &pkthdr, &pkt_data);
        hdr = (TCP_header_part16 *) pkthdr;
        ports[(int)hdr->dest_port] += 1;
        //printf("src: %d dest: %d\n", hdr->src_port, hdr->dest_port);
    }
    for(int i = 0; i < ALL_PORTS; i++) {
        if(ports[i]){
            printf("%d: %d\n", i, ports[i]);
        }
    }

    return 0;
}
