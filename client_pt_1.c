#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "cJSON.c"
#include "cJSON.h"
#include <netinet/ip.h>                
#include <netinet/in.h>

/* Struct to store config information */
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

/* This function parses the config file and populates the struct */
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

/* This function starts a tcp connection and sends config data to server */
void sendConfigToServer(const char *configFile, struct ServerConfig config) {
    int clientSocket;
    struct sockaddr_in serverAddr;
    FILE *fp;
    cJSON *json;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.portTCPPreProbing);

    serverAddr.sin_addr.s_addr = inet_addr(config.serverIPAddress); 

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        printf("error connecting to server\n");
        exit(EXIT_FAILURE);
    }

    json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "Server_IP_Address", config.serverIPAddress);
    cJSON_AddNumberToObject(json, "Source_Port_UDP", config.sourcePortUDP);
    cJSON_AddNumberToObject(json, "Destination_Port_UDP", config.destinationPortUDP);
    cJSON_AddNumberToObject(json, "Destination_Port_TCP_Head_SYN", config.destinationPortTCPHeadSYN);
    cJSON_AddNumberToObject(json, "Destination_Port_TCP_Tail_SYN", config.destinationPortTCPTailSYN);
    cJSON_AddNumberToObject(json, "Port_TCP_Pre_Probing", config.portTCPPreProbing);
    cJSON_AddNumberToObject(json, "Port_TCP_Post_Probing", config.portTCPPostProbing);
    cJSON_AddNumberToObject(json, "UDP_Payload_Size", config.payload);
    cJSON_AddNumberToObject(json, "Inter_Measurement_Time", config.interMeasurementTime);
    cJSON_AddNumberToObject(json, "Number_Of_UDP_Packets", config.numPackets);
    cJSON_AddNumberToObject(json, "TTL", config.timeToLive);

    char *jsonData = cJSON_PrintUnformatted(json);

    send(clientSocket, jsonData, strlen(jsonData), 0);

    cJSON_Delete(json);
    free(jsonData);

    close(clientSocket);
    printf("Configuration data sent to the server.\n");
}


/* This function sends low entropy and high entropy udp packets to server */
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
    int packetID;
    for (int i = 0; i < config.numPackets; i++) {
        packetID = i;
        lowEntropyData[0] = (packetID >> 8) & 0xFF; // Most significant byte
        lowEntropyData[1] = packetID & 0xFF;        // Least significant byte

        sendto(udpSocket, lowEntropyData, sizeof(lowEntropyData), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

        packetID++;
    }
    printf("Low entropy packets sent...\n");

    sleep(config.interMeasurementTime);  
    printf("Waiting inter measurement time...\n");

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

    for (int i = 0; i < config.numPackets; i++) {
        int packetID = i;
        highEntropyData[0] = (packetID >> 8) & 0xFF; // Most significant byte
        highEntropyData[1] = packetID & 0xFF;        // Least significant byte

        sendto(udpSocket, highEntropyData, sizeof(highEntropyData), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

        // Increment the packet ID for the next packet
        packetID++;
    }
        printf("High entropy packets sent...\n");

    close(udpSocket);
}

/* This function establishes tcp connection and receives compression data */
int establishTCPConnection(struct ServerConfig config) {
    int clientSocket;
    struct sockaddr_in serverAddr;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.portTCPPostProbing);
    serverAddr.sin_addr.s_addr = inet_addr(config.serverIPAddress);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }

    int comp_size;
    int compression = recv(clientSocket, &comp_size, sizeof(comp_size), 0);

    if (compression == -1) {
        perror("Error receiving compression information. Please rerun application\n");
        close(clientSocket);
        exit(EXIT_FAILURE);
    } else if (comp_size == 0) {
        printf("No compression detected.\n");
    } else {
        printf("Compression detected.\n");
    }

    close(clientSocket);

    return 0;
}


int main(int argc, char **argv) {
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

    configData[fileSize] = '\0';

    struct ServerConfig config = parseConfig(configData);

    sendConfigToServer(configData, config);

    sleep(1);

    sendUDPPackets(config);

    sleep(1);

    establishTCPConnection(config);

    free(configData);

    return 0;
}

