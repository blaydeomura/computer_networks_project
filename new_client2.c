#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "cJSON.c"
#include "cJSON.h"
#include <arpa/inet.h>
#include <stdlib.h>
#define CONFIG_FILE "config.json" 
#define PCKT_LEN 8192

 
// May create separate header file (.h) for all
// headers' structure
// IP header's structure
struct ipheader {
    unsigned char      iph_ihl:5, /* Little-endian */
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flags;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

/* Structure of a TCP header */
struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
 // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4,      /*little-endian*/
        tcph_hlen:4,     /*length of tcp header in 32-bit words*/
        tcph_fin:1,      /*Finish flag "fin"*/
        tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
        tcph_rst:1,      /*Reset flag */
        tcph_psh:1,      /*Push, sends data to the application*/
        tcph_ack:1,      /*acknowledge*/
        tcph_urg:1,      /*urgent pointer*/
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
}; 


struct ServerConfig {
    const char* serverIPAddress;
    int sourcePortUDP;
    int destinationPortUDP;
    int destinationPortTCPHeadSYN;
    int destinationPortTCPTailSYN;
    int portTCPPreProbing;
    int portTCPPostProbing;
    int payload;
    int interMeasurementTime;
    int numPackets;
    int timeToLive;
};


//Populates the struct
struct ServerConfig parseConfig(const char* jsonConfig) {
    printf("Start of parsing config file\n");
    struct ServerConfig config;
    cJSON* root = cJSON_Parse(jsonConfig);

    if (root != NULL) {
        // gets variable values from json file
        cJSON* serverIP = cJSON_GetObjectItem(root, "Server_IP_Address");
        cJSON* sourcePortUDP = cJSON_GetObjectItem(root, "Source_Port_UDP");
        cJSON* destinationPortUDP = cJSON_GetObjectItem(root, "Destination_Port_UDP");
        cJSON* destinationPortTCPHeadSYN = cJSON_GetObjectItem(root, "Destination_Port_TCP_Head_SYN"); 
        cJSON* destinationPortTCPTailSYN = cJSON_GetObjectItem(root, "Destination_Port_TCP_Tail_SYN");
        cJSON* portTCPPreProbing = cJSON_GetObjectItem(root, "Port_TCP_Pre_Probing");
        cJSON* portTCPPostProbing = cJSON_GetObjectItem(root, "Port_TCP_Post_Probing");
        cJSON* payload = cJSON_GetObjectItem(root, "UDP_Payload_Size");
        cJSON* interMeasurementTime = cJSON_GetObjectItem(root, "Inter_Measurement_Time");
        cJSON* numPackets = cJSON_GetObjectItem(root, "Number_Of_UDP_Packets");
        cJSON* timeToLive = cJSON_GetObjectItem(root, "TTL");

        if (cJSON_IsString(serverIP)) {
            config.serverIPAddress = strdup(serverIP->valuestring);
        }
        if (cJSON_IsNumber(sourcePortUDP)) {
            config.sourcePortUDP = sourcePortUDP->valueint;
        }
        if (cJSON_IsNumber(destinationPortUDP)) {
            config.destinationPortUDP = destinationPortUDP->valueint;
        }
        if (cJSON_IsNumber(destinationPortTCPHeadSYN)) {
            config.destinationPortTCPHeadSYN = destinationPortTCPHeadSYN->valueint;
        }
        if (cJSON_IsNumber(destinationPortTCPTailSYN)) {
            config.destinationPortTCPTailSYN = destinationPortTCPTailSYN->valueint;
        }
        if (cJSON_IsNumber(portTCPPreProbing)) {
            config.portTCPPreProbing = portTCPPreProbing->valueint;
        }
        if (cJSON_IsNumber(portTCPPostProbing)) {
            config.portTCPPostProbing = portTCPPostProbing->valueint;
        }
        if (cJSON_IsNumber(payload)) {
            config.payload = payload->valueint;
        }
        if (cJSON_IsNumber(interMeasurementTime)) {
            config.interMeasurementTime = interMeasurementTime->valueint;
        }
        if (cJSON_IsNumber(numPackets)) {
            config.numPackets = numPackets->valueint;
        }
        if (cJSON_IsNumber(timeToLive)) {
            config.timeToLive = timeToLive->valueint;
        }

        cJSON_Delete(root);
        printf("Configuration data sent to the server.\n");
    } else {
        // Handle JSON parsing error
        printf("Error parsing config file and putting it into struct\n");
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("JSON Error before: %s\n", error_ptr);
        }
        exit(EXIT_FAILURE);
    }

    return config;
}



// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC
unsigned short csum(unsigned short *buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

// setting header and config
void setIPAndTCPHeaders(struct ipheader* ip, struct tcpheader* tcp, const struct ServerConfig* config, int destinationPort, char buffer[]) {
//void setIPAndTCPHeaders(struct ipheader* ip, struct tcpheader* tcp, const struct ServerConfig* config, int destinationPort) {

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
    ip->iph_ident = htons(54321);
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = 6; // TCP
    ip->iph_chksum = 0; // Done by kernel

    //ip->iph_sourceip = inet_addr(config.s);
    ip->iph_destip = inet_addr(config->serverIPAddress);

    // The TCP structure. The source port, spoofed, we accept through the command line
    // tcp->tcph_srcport = htons(atoi(12345));
    tcp->tcph_srcport = htons(12345);

    // The destination port, we accept through command line
    // tcp->tcph_destport = htons(atoi(argv[4]));
    tcp->tcph_destport = htons(destinationPort);

    tcp->tcph_seqnum = htonl(1);
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = 5;
    tcp->tcph_syn = 1;
    tcp->tcph_ack = 0;
    tcp->tcph_win = htons(32767);
    tcp->tcph_chksum = 0; // Done by kernel
    tcp->tcph_urgptr = 0;
    // IP checksum calculation
    ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct ipheader) + sizeof(struct tcpheader)));
}



int main() {
        // Read the JSON configuration file
    FILE* fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        perror("Error opening configuration file");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* configData = (char*)malloc(fileSize + 1);
    if (configData == NULL) {
        perror("Memory allocation error");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fread(configData, 1, fileSize, fp);
    fclose(fp);

    // Null-terminate the JSON data
    configData[fileSize] = '\0';

    //Fill struct config
    struct ServerConfig config = parseConfig(configData);
    
    int sd;

    // No data, just datagram
    char buffer[PCKT_LEN];

    // The size of the headers
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    struct sockaddr_in sin, din;

    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN);

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd < 0) {
        perror("socket() error");
        exit(-1);
    }
    else {
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
    }



//NEEED TO CHANGE LATER
//---COULD BE WRONG----
    // The source is redundant, may be used later if needed
    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = htons(12345);
    din.sin_port = htons(config.destinationPortTCPHeadSYN);
    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    din.sin_addr.s_addr = inet_addr(config.serverIPAddress);


// ----call my set function
    setIPAndTCPHeaders(ip, tcp, &config, config.destinationPortTCPHeadSYN, buffer);

    // Inform the kernel do not fill up the headers' structure, we fabricated our own

if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    perror("setsockopt() error");
    exit(-1);
}
else{
    printf("setsockopt() is OK\n");
}

if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
   perror("sendto() error");
   exit(-1);
}
else {
   printf("Count #%u - sendto() is OK\n", count);
}

close(sd);
return 0;
}

 
