#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "cJSON.c"
#include "cJSON.h"
#include <netinet/ip.h>  
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define CONFIG_FILE "config.json" 


// Headers from "A brief raw sockets..."
//IP Header
struct ipheader {
    unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_id;
    unsigned short int ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short int ip_sum;
    // unsigned int ip_src;
    // unsigned int ip_dst;

    struct in_addr ip_src;
    struct in_addr ip_dst;
}; /* total ip header length: 20 bytes (=160 bits) */

// icmp Header
struct icmpheader {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_cksum;
    /* The following data structures are ICMP type specific */
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
}; /* total icmp header length: 8 bytes (=64 bits) */

//UDP header
struct udpheader {
 unsigned short int uh_sport;
 unsigned short int uh_dport;
 unsigned short int uh_len;
 unsigned short int uh_check;
}; /* total udp header length: 8 bytes (=64 bits) */

// TCP header
struct tcpheader {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
}; /* total tcp header length: 20 bytes (=160 bits) */


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

// Read from config file
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


unsigned short checksum(unsigned short* buffer, int size) {
    unsigned long sum;
    for (sum = 0; size > 0; size--)
        sum += *buffer++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
//   return ~sum;
    return (unsigned short)(~sum);
}



// void setIPAndTCPHeaders(struct ip* ip_header, struct tcphdr* tcp_header, const struct ServerConfig* config, int destinationPort) {
void setIPAndTCPHeaders(struct ipheader* ip_header, struct tcpheader* tcp_header, const struct ServerConfig* config, int destinationPort) {

    ip_header->ip_hl = 5;  // Header length (5 words)
    ip_header->ip_v = 4;   // IPv4
    ip_header->ip_tos = 0; // Type of Service
    ip_header->ip_len = sizeof(struct ipheader) + sizeof(struct tcpheader); // Total length
    ip_header->ip_id = 54321; // Identification (in host byte order)
    ip_header->ip_off = 0; // Fragment offset
    ip_header->ip_ttl = config->timeToLive;
    ip_header->ip_p = 6;
    ip_header->ip_sum = 0;
    ip_header->ip_dst.s_addr = inet_addr(config->serverIPAddress);


    tcp_header->th_sport = htons(12345);
    tcp_header->th_dport = htons(destinationPort);
    tcp_header->th_seq = random();
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535); // max window size
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    ip_header->ip_sum = checksum((unsigned short *)ip_header, sizeof(struct ipheader) / 2);
    tcp_header->th_sum = checksum((unsigned short *)tcp_header, sizeof(struct tcpheader) / 2);
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


//Start raw socket programming
    //setup addr for HEAD syn socket
    struct sockaddr_in addrSynHead;
    addrSynHead.sin_family = AF_INET;
    addrSynHead.sin_port = htons(config.destinationPortTCPHeadSYN);
    printf("Destination Port TCP Head SYN: %d\n", config.destinationPortTCPHeadSYN);
    addrSynHead.sin_addr.s_addr = inet_addr(config.serverIPAddress);
    printf("Server IP Address: %s\n", config.serverIPAddress);


//add in addr for udp packet
//add in addr for TAIL syn packet

    int headSynSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (headSynSocket == -1) {
        perror("Head Syn Socket creation error");
        return -1;               
    }

    int one = 1;
    const int *val = &one;
    // if (setsockopt (headSynSocket, IPPROTO_RAW, IP_HDRINCL, val, sizeof (one)) < 0) {
    if (setsockopt(headSynSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {

        printf("Warning: Cannot set HDRINCL!\n");
        close(headSynSocket);
        return -1;
    }
    else{
        printf("Head syn packet creation worked\n");
    }

    // Allocate memory for the packet
    char packet[4096];  // Adjust the size as needed

    // Set up IP and TCP headers
    struct ipheader *ip_header = (struct ipheader *)packet;
    struct tcpheader *tcp_header = (struct tcpheader *)(packet + sizeof(struct ipheader));

    // Set the packet headers
    setIPAndTCPHeaders(ip_header, tcp_header, &config, config.destinationPortTCPHeadSYN);

    if (sendto(headSynSocket, packet, ip_header->ip_len, 0, (struct sockaddr *)&addrSynHead, sizeof(struct sockaddr_in)) < 0) {
        perror("Packet send error");
    } else {
        printf("SYN packet sent successfully\n");
    }

    // Close the raw socket
    close(headSynSocket);







    return 0;

}



















// // void setIPAndTCPHeaders(struct ip* ip_header, struct tcphdr* tcp_header, const struct ServerConfig* config, int destinationPort) {
// void setIPAndTCPHeaders(struct ipheader* ip_header, struct tcpheader* tcp_header, const struct ServerConfig* config, struct sockaddr_in addrSynHead, int destinationPort, char *datagram) {

//     ip_header->ip_hl = 5;  // Header length (5 words)
//     ip_header->ip_v = 4;   // IPv4
//     ip_header->ip_tos = 0; // Type of Service
//     ip_header->ip_len = sizeof(struct ipheader) + sizeof(struct tcpheader); // Total length
//     ip_header->ip_id = 54321; // Identification (in host byte order)
//     ip_header->ip_off = 0; // Fragment offset
//     ip_header->ip_ttl = config->timeToLive;
//     ip_header->ip_p = 6;
//     ip_header->ip_sum = 0;
//     ip_header->ip_dst.s_addr = addrSynHead.sin_addr.s_addr;

//     tcp_header->th_sport = htons(config->sourcePortUDP);
//     tcp_header->th_dport = htons(destinationPort);
//     tcp_header->th_seq = random();
//     tcp_header->th_ack = 0;
//     tcp_header->th_off = 0;
//     tcp_header->th_flags = TH_SYN;
//     tcp_header->th_win = htons(65535); // max window size
//     tcp_header->th_sum = 0;
//     tcp_header->th_urp = 0;

//     ip_header->ip_sum = checksum((unsigned short *)datagram, ip_header->ip_len >> 1);

// }

// int main() {
//     // Read the JSON configuration file
//     FILE* fp = fopen(CONFIG_FILE, "r");
//     if (fp == NULL) {
//         perror("Error opening configuration file");
//         exit(EXIT_FAILURE);
//     }

//     fseek(fp, 0, SEEK_END);
//     long fileSize = ftell(fp);
//     fseek(fp, 0, SEEK_SET);
//     char* configData = (char*)malloc(fileSize + 1);
//     if (configData == NULL) {
//         perror("Memory allocation error");
//         fclose(fp);
//         exit(EXIT_FAILURE);
//     }
//     fread(configData, 1, fileSize, fp);
//     fclose(fp);

//     // Null-terminate the JSON data
//     configData[fileSize] = '\0';

//     //Fill struct config
//     struct ServerConfig config = parseConfig(configData);




// //Start raw socket programming
//     //setup addr for HEAD syn socket
//     struct sockaddr_in addrSynHead;
//     addrSynHead.sin_family = AF_INET;
//     addrSynHead.sin_port = htons(config.destinationPortTCPHeadSYN);
//     printf("Destination Port TCP Head SYN: %d\n", config.destinationPortTCPHeadSYN);
//     addrSynHead.sin_addr.s_addr = inet_addr(config.serverIPAddress);
//     printf("Server IP Address: %s\n", config.serverIPAddress);


// //add in addr for udp packet

// //add in addr for TAIL syn packet

//     int headSynSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//     if (headSynSocket == -1) {
//         perror("Head Syn Socket creation error");
//         return -1;               
//     }
    


//     int one = 1;
//     const int *val = &one;
//     if (setsockopt (headSynSocket, IPPROTO_RAW, IP_HDRINCL, val, sizeof (one)) < 0) {
//         printf("Warning: Cannot set HDRINCL!\n");
//     }
//     else{
//         printf("Head syn packet creation worked\n");
//     }
//     // int one = 1;
//     // if (setsockopt(headSynSocket, IPPROTO_RAW, IP_HDRINCL, &one, sizeof(one)) < 0)
//     // {
//     //     printf("Warning: Cannot set HDRINCL in head!\n");
//     //     exit(1); // leave the program
//     // }



//     // printf("Server IP Address: %s\n", config.serverIPAddress);
//     // printf("Source Port UDP: %d\n", config.sourcePortUDP);
//     // printf("Destination Port UDP: %d\n", config.destinationPortUDP);
//     // printf("Destination Port TCP Head SYN: %d\n", config.destinationPortTCPHeadSYN);
//     // printf("Destination Port TCP Tail SYN: %d\n", config.destinationPortTCPTailSYN);
//     // printf("Port TCP Pre Probing: %d\n", config.portTCPPreProbing);
//     // printf("Port TCP Post Probing: %d\n", config.portTCPPostProbing);
//     // printf("UDP Payload Size: %d\n", config.payload);
//     // printf("Intermeasurement Time: %d\n", config.interMeasurementTime);
//     // printf("Number of UDP Packets: %d\n", config.numPackets);
//     // printf("Time To Live (TTL): %d\n", config.timeToLive);


//     return 0;

// }


//gcc -o client_2 client2.c -lcjson -I/usr/local/opt/cjson/include -L/usr/local/opt/cjson/lib

//sudo gcc -o client2 client_pt_2.c -lcjson -I/usr/local/opt/cjson/include -L/usr/local/opt/cjson/lib