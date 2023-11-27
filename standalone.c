/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
 *
 *  The code that deals with raw sockets for setting the SYN flags,
 *  IP/TCP headers, and checksum are done by P.D. Buchan.
 *  The code comes from: https://www.pdbuchan.com/rawsock/tcp4.c
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <errno.h>            
#include "cJSON.c"
#include "cJSON.h"
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#define CONFIG_FILE "config.json"
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define RST_TIMEOUT_SEC 45


/* Function prototypes */
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

/* Struct to store configuration data */
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

/* This function parses config file and populates struct */
struct ServerConfig parseConfig(const char* jsonConfig) {
    struct ServerConfig config;
    cJSON* root = cJSON_Parse(jsonConfig);

    if (root != NULL) {
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
        printf("Error parsing config file and putting it into struct\n");
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("JSON Error before: %s\n", error_ptr);
        }
        exit(EXIT_FAILURE);
    }

    return config;
}


/* ----------- Code from P.D. Buchan starts here ----------- */

/* This function calculates checksum */
uint16_t
checksum (uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}


/* This function builds IPv4 TCP pseudo-header and calls checksum function. */
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr) {

  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr));
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}

/* This function allocates memory for an array of chars. */
char *
allocate_strmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

/* This function allocates memory for an array of unsigned chars.*/
uint8_t *
allocate_ustrmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

/* This function allocates memory for an array of ints.*/
int *
allocate_intmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

/* This function fills out our IP and TCP headers in syn packets */
int setIPAndTCPHeaders(const struct ServerConfig* config, int destinationPort) {

  int i, status, sd, *ip_flags, *tcp_flags;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  uint8_t *packet;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;
  void *tmp;


  //----------------DECLARE HEADERS----------------
  // Allocate memory for various arrays.
  packet = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);
  tcp_flags = allocate_intmem (8);
  //-----------------------------------------------

  // Interface to send packet through.
  strcpy (interface, "enp0s1");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    return (1);
  }

  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    perror ("ioctl() failed to find interface ");
    return (1);
  }
  close (sd);

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "192.168.64.2");

  // Destination URL or IPv4 address: you need to fill this out
  char destinationPortStr[20];
  snprintf(destinationPortStr, sizeof(destinationPortStr), "%d", destinationPort);
  strcpy (target, destinationPortStr);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target: %s\n", gai_strerror (status));
    return (1);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // IPv4 header
  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;
  // Type of service (8 bits)
  iphdr.ip_tos = 0;
  // Total length of datagram (16 bits): IP header + TCP header
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN);
  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);
  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
  // Zero (1 bit)
  ip_flags[0] = 0;
  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;
  // More fragments following flag (1 bit)
  ip_flags[2] = 0;
  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;
  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);
  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;
  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;
  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
    exit (1);
  }


  const char* destinationIP = "192.168.64.3";
  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, destinationIP, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
    exit (1);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // TCP header
  // Source port number (16 bits)
  tcphdr.th_sport = htons (1234);
  // Destination port number (16 bits)
  tcphdr.th_dport = htons (destinationPort);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl (0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (1);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr);

  // Prepare packet.

  // First part is an IPv4 header.
  memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

  // Next part of packet is upper layer protocol header.
  memcpy ((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (1);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (1);
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (1);
  }

  // Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (1);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (packet);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);
  free (tcp_flags);
}
/* ----------- Code from P.D. Buchan ends here ----------- */



/* ----------- Code from myself begins below -------------*/

/* This function sends low and high entropy packets */
void sendUDPPackets(struct ServerConfig config) {
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0) {
        perror("Error creating UDP socket");
        return;
    }

    int df_flag = 1; // Set to 1 to enable DF
    if (setsockopt(udpSocket, IPPROTO_IP, IP_MTU_DISCOVER, &df_flag, sizeof(df_flag)) < 0) {
        perror("Error setting DF flag for UDP packets");
        close(udpSocket);
        return;
    }

    struct sockaddr_in clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(config.sourcePortUDP); // Set the source port here
    clientAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udpSocket, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) < 0) {
        perror("Error binding UDP socket");
        close(udpSocket);
        return;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.destinationPortUDP);              // SETS THE SOURCE PORT HERE
    serverAddr.sin_addr.s_addr = inet_addr(config.serverIPAddress);

    char lowEntropyData[1000];  // Maximum UDP packet size 
    memset(lowEntropyData, 0, sizeof(lowEntropyData));  // Fill with zeros 

    for (int i = 0; i < config.numPackets; i++) {
        // Set the packet ID in the first 2 bytes
        int packetID = i;
        lowEntropyData[0] = (packetID >> 8) & 0xFF; // Most significant byte
        lowEntropyData[1] = packetID & 0xFF;        // Least significant byte
    
    	int ttl_value = config.timeToLive;
    	if (setsockopt(udpSocket, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value)) < 0) {
        	perror("Error setting TTL for UDP packets");
        	close(udpSocket);
        	return;
    	}
        
    ssize_t sentBytes = sendto(udpSocket, lowEntropyData, sizeof(lowEntropyData), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    if (sentBytes == -1) {
        perror("Error sending UDP packet");
        close(udpSocket);
        return;
    } else if (sentBytes != sizeof(lowEntropyData)) {
        fprintf(stderr, "Warning: Not all bytes of the packet were sent.\n");
    }

        packetID++;
    }
    printf("Low entropy packets sent...\n");

    //  Wait for Inter-Measurement Time (γ) seconds
    sleep(config.interMeasurementTime);  // Adjust the sleep time as needed
    printf("Waiting inter measurement time...\n");

    // Send high entropy packets
    char highEntropyData[1000];
    FILE *randomFile = fopen("random_file", "rb");
    if (randomFile != NULL) {
        fread(highEntropyData, sizeof(char), sizeof(highEntropyData), randomFile);
        fclose(randomFile);
    } else {
        perror("Error opening random_file");
        close(udpSocket);
        return;
    }
      
    int packetID;
    for (int i = 0; i < config.numPackets; i++) {
        packetID = i;
        highEntropyData[0] = (packetID >> 8) & 0xFF; // Most significant byte
        highEntropyData[1] = packetID & 0xFF;        // Least significant byte

    	int ttl_value = config.timeToLive;
    	if (setsockopt(udpSocket, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value)) < 0) {
        	perror("Error setting TTL for UDP packets");
        	close(udpSocket);
        	return;
    	}

        sendto(udpSocket, highEntropyData, sizeof(highEntropyData), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

        packetID++;
    }
    printf("Sent high entropy packets...\n");

    close(udpSocket);
}


/* This function sends SYN and UDP packets */
void* sendPackets(void* arg) {
    struct ServerConfig* config = (struct ServerConfig*)arg;
    setIPAndTCPHeaders(config, config->destinationPortTCPHeadSYN);

    sendUDPPackets(*config);

    setIPAndTCPHeaders(config, config->destinationPortTCPTailSYN);

    pthread_exit(NULL);
}

/* This function is for errros */
void rst_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}


/* This function listens for RST packets */
void* listenForRST(void* arg) {
    struct ServerConfig* config = (struct ServerConfig*)arg;
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) 
        rst_error("Error opening socket");

    // Set socket options to receive all TCP packets
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
        rst_error("Error setting socket options");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        rst_error("Error binding socket");

    struct timeval start_time, end_time;
    int rst_count = 0;

    // Loop to listen for RST packets
    while (1) {
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;
        char buffer[65536]; // Buffer to store incoming packets

        // Receive packet
        ssize_t packet_size = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                       (struct sockaddr *)&client_addr, &client_len);
        if (packet_size < 0)
            rst_error("Error receiving packet");

        // Extract IP and TCP headers
        ip_header = (struct iphdr *)buffer;
        tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

        // Check if it's an RST packet
        if (tcp_header->rst) {
            if (rst_count == 0) {
                gettimeofday(&start_time, NULL);
            } else if (rst_count == 1) {
                gettimeofday(&end_time, NULL);

                // Calculate the time difference and need to account for intermeasurement time
                double time_diff = difftime(end_time.tv_sec, start_time.tv_sec + config->interMeasurementTime) + ((double)(end_time.tv_usec - start_time.tv_usec + config->interMeasurementTime) / 1000000);

		// Check if compression is detected
                if (time_diff >= 0.1) {  // 100 milliseconds
                    printf("Compression detected!\n");
                } else {
                    printf("Compression not detected.\n");
                }

                // Cleanup and exit
                close(sockfd);
                exit(EXIT_SUCCESS);
            }

            rst_count++;
        }

        /* CODE BELOW IMPLEMENTS TIMEOUT IF RST IS FAILED TO BE RECEICED */
	// Check for timeout
        struct timeval current_time;
        gettimeofday(&current_time, NULL);

        if (current_time.tv_sec - start_time.tv_sec > RST_TIMEOUT_SEC) {
            printf("Failed to detect due to insufficient information\n");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

    }
    pthread_exit(NULL);
}



int
main (int argc, char **argv) {
    const char* configFileName;
    if (argc > 1) {
	configFileName = argv[1];
    }
    else {
	printf("Please correct the commandline argument.\n");
	exit(EXIT_FAILURE);
    }

    // Read the JSON configuration file
    FILE* fp = fopen(configFileName, "r");
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


    /* multithread this application */
    pthread_t sendThread, listenThread;

    // Create threads
    if (pthread_create(&sendThread, NULL, sendPackets, (void*)&config) != 0) {
        perror("Error creating send thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&listenThread, NULL, listenForRST, (void*)&config) != 0) {
        perror("Error creating listen thread");
        exit(EXIT_FAILURE);
    }

    // Wait for threads to finish
    if (pthread_join(sendThread, NULL) != 0) {
        perror("Error joining send thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_join(listenThread, NULL) != 0) {
        perror("Error joining listen thread");
        exit(EXIT_FAILURE);
    }

    return 0;
}
