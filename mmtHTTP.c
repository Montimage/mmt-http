/**
 * MMT-HTTP
 * Provides information about the HTTP traffics
 * @author: Montimage
 * @license: Montimage
 * @creator: Luong NGUYEN
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

mmt_handler_t *mmt_handler;// MMT handler
pcap_t *pcap; // Pcap handler
struct pcap_stat pcs; /* packet capture filter stats */
int pcap_bs = 0; // pcap handler buffer
int cleaned = 0;
/**
 * MMT HTTP request structure
*/
typedef struct mmt_http_stats_struct{
    uint64_t method;
    uint64_t user_agent;
    uint64_t uri;
    uint64_t content_len;
    uint64_t content_type;
    uint64_t host;
    uint64_t referer;
    uint64_t server;
    uint64_t response;
}mmt_http_stats_t;

/**
 * MMT HTTP session structure
*/
typedef struct mmt_http_session_struct{
    uint64_t ip_session_id;
    uint64_t http_session_id;
    char * method;
    char * user_agent;
    char * uri;
    int content_len;
    char * content_type;
    char * host;
    char * server;
    char * referer;
    char * response;
} mmt_http_session_t;


mmt_http_stats_t http_stats;
/**
 * Show http attributes statistics
 * @param http_stats [description]
 */
void mmt_http_stats_show( mmt_http_stats_t * http_stats){
    printf("\n HTTP statistic:\n");
    printf("\t method: %lu\n",http_stats->method);
    printf("\t user_agent: %lu\n",http_stats->user_agent);
    printf("\t uri: %lu\n",http_stats->uri);
    printf("\t content_len: %lu\n",http_stats->content_len);
    printf("\t content_type: %lu\n",http_stats->content_type);
    printf("\t host: %lu\n",http_stats->host);
    printf("\t server: %lu\n",http_stats->server);
    printf("\t referer: %lu\n",http_stats->referer);
    printf("\t response: %lu\n",http_stats->response);
}

/**
 * Initialize a pcap handler
 * @param  iname       interface name
 * @param  buffer_size buffer size (MB)
 * @param  snaplen     packet snaplen
 * @return             NULL if cannot create pcap handler
 *                     a pointer points to a new pcap handle
 */
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen){
    pcap_t * my_pcap;
    char errbuf[1024];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        exit(0);
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        exit(0);
    }
    return my_pcap;
}

/**
 * Show help message
 * @param prg_name program name
 */
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
 * parser input parameter
 * @param argc     number of parameter
 * @param argv     parameter string
 * @param filename input source -> file name or interaface name
 * @param type     TRACE_FILE or LIVE_INTERFACE
 */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:b:h")) != EOF) {
        switch (opt) {
            case 't':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
            
            case 'b':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            pcap_bs = atoi(optarg);
            break;

            case 'h':
            default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }

    return;
}

/**
 * Packet handler
 */
int packet_handler(const ipacket_t * ipacket, void * user_args){

    uint32_t * ip_src = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_SRC);
    uint32_t * ip_dst = (uint32_t *)get_attribute_extracted_data(ipacket,PROTO_IP,IP_DST);
    
    if(ip_src == NULL || ip_dst == NULL){
        return 0;
    }

    mmt_header_line_t * method = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","method");
    if(method!=NULL){
        
        printf("\n\t - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
        printf("\t Request: %s -------> ",inet_ntoa(*(struct in_addr*)ip_src));
        printf("%s \n",inet_ntoa(*(struct in_addr*)ip_dst));
        
        http_stats.method++;
        char * mvalue = NULL;
        mvalue = malloc(method->len+1);
        memcpy(mvalue,method->ptr,method->len);
        printf("\t Method: %s\n",mvalue);
        mvalue[method->len]='\0';
        free(mvalue);
        mvalue = NULL;
    }

    mmt_header_line_t * response = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","response");
    if(response!=NULL){
        printf("\n\t Response: %s <------- ",inet_ntoa(*(struct in_addr*)ip_dst));
        printf("%s \n",inet_ntoa(*(struct in_addr*)ip_src));
        
        http_stats.response++;
        char * rvalue = NULL;
        rvalue = malloc(response->len+1);
        memcpy(rvalue,response->ptr,response->len);
        rvalue[response->len]='\0';
        printf("\t Response code : %s\n",rvalue);
        free(rvalue);
        rvalue = NULL;
    }

    mmt_header_line_t * uri = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","uri");
    if(uri!=NULL){
        http_stats.uri++;        
        char * uvalue = NULL;
        uvalue = malloc(uri->len+1);
        memcpy(uvalue,uri->ptr,uri->len);
        uvalue[uri->len]='\0';
        printf("\t URI: %s\n",uvalue);
        free(uvalue);
        uvalue = NULL;
    }

    mmt_header_line_t * host = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","host");
    if(host!=NULL){
        http_stats.host++;
        char * hvalue = NULL;
        hvalue = malloc(host->len+1);
        memcpy(hvalue,host->ptr,host->len);
        hvalue[host->len]='\0';
        printf("\t Host: %s\n",hvalue);
        free(hvalue);
        hvalue = NULL;
    }

    
    mmt_header_line_t * content_type = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","content_type");
    if(content_type!=NULL){
        http_stats.content_type++;
        char * ctvalue = NULL;
        ctvalue = malloc(content_type->len+1);
        memcpy(ctvalue,content_type->ptr,content_type->len);
        ctvalue[content_type->len]='\0';
        printf("\t Content-type: %s\n",ctvalue);
        free(ctvalue);
        ctvalue = NULL;
    }
    mmt_header_line_t * content_len = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","content_len");
    if(content_len!=NULL){
        http_stats.content_len++;
        char * clvalue = NULL;
        clvalue = malloc(content_len->len+1);
        memcpy(clvalue,content_len->ptr,content_len->len);
        clvalue[content_len->len]='\0';
        printf("\t Content-length: %s\n",clvalue);
        free(clvalue);
        clvalue = NULL;
    }
    mmt_header_line_t * user_agent = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","user_agent");

    if(user_agent!=NULL){
        http_stats.user_agent++;
        char * uavalue = NULL;
        uavalue = malloc(user_agent->len+1);
        memcpy(uavalue,user_agent->ptr,user_agent->len);
        uavalue[user_agent->len]='\0';
        printf("\t User-agent: %s\n",uavalue);
        free(uavalue);
        uavalue = NULL;
    }

    mmt_header_line_t * server = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","server");

    if(server!=NULL){
        http_stats.server++;
        char * svalue = NULL;
        svalue = malloc(server->len+1);
        memcpy(svalue,server->ptr,server->len);
        svalue[server->len]='\0';
        printf("\t Server: %s\n",svalue);
        free(svalue);
        svalue = NULL;
    }

    mmt_header_line_t * referer = (mmt_header_line_t *) get_attribute_extracted_data_by_name(ipacket,"http","referer");

    if(referer!=NULL){
        http_stats.referer++;
        char * refvalue = NULL;
        refvalue = malloc(referer->len+1);
        memcpy(refvalue,referer->ptr,referer->len);
        refvalue[referer->len]='\0';
        printf("\t Referer: %s\n",refvalue);
        free(refvalue);
        refvalue = NULL;
    }
    return 0;
}

/**
 * Analyse from an interface
 * @param user     user argument
 * @param p_pkthdr pcap header
 * @param data     packet data
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

/**
 * Clean resource when the program finished
 */
void clean() {
    if(cleaned == 1) return;
    cleaned = 1;
    mmt_http_stats_show(&http_stats);
    // printf("\n[info] Cleaning....\n");
    //Close the MMT handler
    mmt_close_handler(mmt_handler);
    // printf("[info] Closed mmt_handler\n");
    
    //Close MMT
    close_extraction();
    // printf("[info] Closed extraction \n");

    // Show pcap statistic if capture from an interface
    if (pcap_stats(pcap, &pcs) < 0) {
        // printf("[info] pcap_stats does not exist\n");
        // (void) printf("[info] pcap_stats: %s\n", pcap_geterr(pcap));
    } else {
        (void) printf("[info] \n%12d packets received by filter\n", pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by driver (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
        fflush(stderr);
    }
    
    // printf("[info] Closing pcaps...!\n");
    if (pcap != NULL) pcap_close(pcap);
    // printf("[info] Finished cleaning....\n");
    printf("\nGOOD BYE ....\n");
}

/**
 * Handler signals during excutation time
 * @param type signal type
 */
void signal_handler(int type) {
    printf("\n[info] reception of signal %d\n", type);
    fflush( stderr );
    clean();
    exit(0);
}

/**
 * Main program start from here
 * @param  argc [description]
 * @param  argv [description]
 * @return      [description]
 */
int main(int argc, char ** argv) {
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
    printf("|\t\t MMT-HTTP\n");
    printf("|\t MMT-SDK version: %s\n",mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
    sigset_t signal_set;

    char mmt_errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1]; // interface name or path to pcap file
    int type; // Online or offline mode

    // Parse option
    parseOptions(argc, argv, filename, &type);

    //Initialize MMT
    init_extraction();

    //Initialize MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed for the following reason: %s\n", mmt_errbuf );
        return EXIT_FAILURE;
    }
    // Disable session analysis
    disable_protocol_analysis(mmt_handler,get_protocol_id_by_name("ftp"));
    disable_protocol_analysis(mmt_handler,get_protocol_id_by_name("ndn"));
    disable_protocol_analysis(mmt_handler,get_protocol_id_by_name("ndn_http"));
    disable_protocol_analysis(mmt_handler,get_protocol_id_by_name("radius"));
    disable_protocol_analysis(mmt_handler,get_protocol_id_by_name("rtp"));
    // Disable classification of protocol over UDP
    disable_protocol_classification(mmt_handler,get_protocol_id_by_name("udp"));

    // Register extraction attribute
    register_extraction_attribute(mmt_handler,PROTO_IP,IP_SRC);
    register_extraction_attribute(mmt_handler,PROTO_IP,IP_DST);
    register_extraction_attribute_by_name(mmt_handler,"http","method"); 
    register_extraction_attribute_by_name(mmt_handler,"http","host"); 
    register_extraction_attribute_by_name(mmt_handler,"http","response"); 
    register_extraction_attribute_by_name(mmt_handler,"http","uri"); 
    register_extraction_attribute_by_name(mmt_handler,"http","content_type"); 
    register_extraction_attribute_by_name(mmt_handler,"http","user_agent"); 
    register_extraction_attribute_by_name(mmt_handler,"http","content_len");
    register_extraction_attribute_by_name(mmt_handler,"http","server");
    register_extraction_attribute_by_name(mmt_handler,"http","referer"); 
    
    // Register packet handler function
    register_packet_handler(mmt_handler,1,packet_handler, NULL);
    // register_attribute_handler_by_name(mmt_handler,"http","uri",uri_handler, NULL ,NULL); 

    // Handle signal
    sigfillset(&signal_set);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pkthdr header; // MMT packet header
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason\n");
            return EXIT_FAILURE;
        }
        const u_char *data;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        if(pcap_bs == 0){
            printf("[info] Use default buffer size: 50 (MB)\n");
        }else{
            printf("[info] Use buffer size: %d (MB)\n",pcap_bs);
        }
        // ONLINE MODE
        pcap = init_pcap(filename,pcap_bs,65535);

        if (!pcap) {
            fprintf(stderr, "[error] creating pcap failed for the following reason: %s\n", mmt_errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    clean();

    return EXIT_SUCCESS;

}
