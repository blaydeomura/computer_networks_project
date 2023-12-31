#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "cJSON.c"
#include "cJSON.h"
#include <sys/time.h> 
#include <time.h>     
#include <math.h>     
#include <netinet/in.h>
#define MAX_PACKET_SIZE 2000  

/*
 * This struct holds all of the information we need from our config file
*/
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

/* 
 * This function parses the config file and stores data into struct 
 */
void handleConfigData(cJSON *json, struct ServerConfig* config) {

    cJSON* serverIP = cJSON_GetObjectItem(json, "Server_IP_Address");
    cJSON* sourcePortUDP = cJSON_GetObjectItem(json, "Source_Port_UDP");
    cJSON* destinationPortUDP = cJSON_GetObjectItem(json, "Destination_Port_UDP");
    cJSON* destinationPortTCPHeadSYN = cJSON_GetObjectItem(json, "Destination_Port_TCP_Head_SYN"); 
    cJSON* destinationPortTCPTailSYN = cJSON_GetObjectItem(json, "Destination_Port_TCP_Tail_SYN");
    cJSON* portTCPPreProbing = cJSON_GetObjectItem(json, "Port_TCP_Pre_Probing");
    cJSON* portTCPPostProbing = cJSON_GetObjectItem(json, "Port_TCP_Post_Probing");
    cJSON* payload = cJSON_GetObjectItem(json, "UDP_Payload_Size");
    cJSON* interMeasurementTime = cJSON_GetObjectItem(json, "Inter_Measurement_Time");
    cJSON* numPackets = cJSON_GetObjectItem(json, "Number_Of_UDP_Packets");
    cJSON* timeToLive = cJSON_GetObjectItem(json, "TTL");

    if (cJSON_IsString(serverIP)) {
        config->serverIPAddress = strdup(serverIP->valuestring);
    }
    if (cJSON_IsNumber(sourcePortUDP)) {
        config->sourcePortUDP = sourcePortUDP->valueint;
    }
    if (cJSON_IsNumber(destinationPortUDP)) {
        config->destinationPortUDP = destinationPortUDP->valueint;

    }
    if (cJSON_IsNumber(destinationPortTCPHeadSYN)) {
        config->destinationPortTCPHeadSYN = destinationPortTCPHeadSYN->valueint;
    }
    if (cJSON_IsNumber(destinationPortTCPTailSYN)) {
        config->destinationPortTCPTailSYN = destinationPortTCPTailSYN->valueint;
    }
    if (cJSON_IsNumber(portTCPPreProbing)) {
        config->portTCPPreProbing = portTCPPreProbing->valueint;
    }
    if (cJSON_IsNumber(portTCPPostProbing)) {
        config->portTCPPostProbing = portTCPPostProbing->valueint;
    }
    if (cJSON_IsNumber(payload)) {
        config->payload = payload->valueint;
    }
    if (cJSON_IsNumber(interMeasurementTime)) {
        config->interMeasurementTime = interMeasurementTime->valueint;
    }
    if (cJSON_IsNumber(numPackets)) {
        config->numPackets = numPackets->valueint;
    }
    if (cJSON_IsNumber(timeToLive)) {
        config->timeToLive = timeToLive->valueint;
    }
    printf("Parsed config data\n");
}

/* 
 * This function receives the config file from client via tcp connection 
 */
void receiveConfigFromClient(struct ServerConfig* serverConfig, int serverPort) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize = sizeof(clientAddr);
    cJSON *json;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);    
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrSize);
    if (clientSocket == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    char buffer[2048];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        perror("Error receiving data from client");
        close(clientSocket);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    buffer[bytesRead] = '\0';

    json = cJSON_Parse(buffer);
    if (json == NULL) {
        perror("Error parsing JSON data");
        close(clientSocket);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    handleConfigData(json, serverConfig);

    cJSON_Delete(json);

    close(clientSocket);
    close(serverSocket);

    printf("Configuration data received from the client.\n");
}

/* 
 * This function receives UDP packets from the client and 
 * then creates a tcp connection and sends over compression data
 */
void receiveUDPPackets(struct ServerConfig config) {
    struct timeval startTimeLowEntropy, endTimeLowEntropy;
    struct timeval startTimeHighEntropy, endTimeHighEntropy;

    printf("Receiving udp packet process...\n");
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize = sizeof(clientAddr);
    char buffer[MAX_PACKET_SIZE];

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.destinationPortUDP);
    serverAddr.sin_addr.s_addr = inet_addr(config.serverIPAddress);

    if (bind(udpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    gettimeofday(&startTimeLowEntropy, NULL); // Record start time for low entropy

    for (int i = 0; i < config.numPackets; i++) {
        int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrSize);

        if (bytesRead <= 0) {
            perror("Error receiving low entropy data from client");
            break;
        }

        buffer[bytesRead] = '\0';
    }
    gettimeofday(&endTimeLowEntropy, NULL); // Record end time for low entropy
    printf("Received low entropy packets...\n");

    //  Wait for Inter-Measurement Time 
    sleep(config.interMeasurementTime); 

    gettimeofday(&startTimeHighEntropy, NULL); // Record start time for high entropy

    for (int i = 0; i < config.numPackets; i++) {
        int bytesRead = recvfrom(udpSocket, buffer, config.payload, 0, (struct sockaddr*)&clientAddr, &addrSize);
        
	if (bytesRead <= 0) {
            perror("Error receiving high entropy data from client");
            break;
        }

        buffer[bytesRead] = '\0';
    }
    gettimeofday(&endTimeHighEntropy, NULL); // Record end time for high entropy

    close(udpSocket);

    /* Start the 2nd tcp connection to send compression data */

    int serverSocket1, clientSocket1;
    struct sockaddr_in serverAddr1, clientAddr1;

    serverSocket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket1 == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    if (setsockopt(serverSocket1, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        perror("Error setting SO_REUSEADDR option");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr1, 0, sizeof(serverAddr1));
    serverAddr1.sin_family = AF_INET;
    serverAddr1.sin_port = htons(config.portTCPPostProbing);
    serverAddr1.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket1, (struct sockaddr*)&serverAddr1, sizeof(serverAddr1)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket1, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    clientSocket1 = accept(serverSocket1, (struct sockaddr*)&clientAddr1, &addrSize);
    if (clientSocket1 == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    double timeDifferenceLowEntropy = (endTimeLowEntropy.tv_sec - startTimeLowEntropy.tv_sec) + 1e-6 * (endTimeLowEntropy.tv_usec - startTimeLowEntropy.tv_usec);
    printf("timeDifferenceLowEntropy: %f\n", timeDifferenceLowEntropy);

    double timeDifferenceHighEntropy = (endTimeHighEntropy.tv_sec - startTimeHighEntropy.tv_sec + 1) + 1e-6 * (endTimeHighEntropy.tv_usec - startTimeHighEntropy.tv_usec + 1);
    printf("timeDifferenceHighEntropy: %f\n", timeDifferenceHighEntropy);


int compressionDetected = (fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy) > 0.1);     

    printf("Time difference: %f\n", fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy));
    printf("Compression detected: %d\n", compressionDetected);

    if (send(clientSocket1, &compressionDetected, sizeof(int), 0) == -1) {
	    perror("Error sending compression detected boolean: \n");
	    exit(EXIT_FAILURE);
    }

    close(clientSocket1);
    close(serverSocket1);
}



int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int serverPort = atoi(argv[1]); // Convert the port number from string to integer
 

    struct ServerConfig serverConfig; // Declare the server's configuration struct
    
    receiveConfigFromClient(&serverConfig, serverPort);

    receiveUDPPackets(serverConfig);

    return 0;
}

