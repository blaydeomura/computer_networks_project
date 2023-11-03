#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>  
#include <sys/time.h> 
#include <time.h>     
#include <math.h>     


#define SERVER_TCP_PORT 7777  // Comes from commandline

#define MAX_PACKET_SIZE 2000  // for UDP, is this right?

//Define the struct of config file
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

void handleConfigData(cJSON *json, struct ServerConfig* config) {

    // gets variable values from json file
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


    //Populate struct from pointers above
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










//void receiveConfigFromClient() {
void receiveConfigFromClient(struct ServerConfig* serverConfig) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize = sizeof(clientAddr);
    cJSON *json;

    // 1. Server creates socket 
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_TCP_PORT);    //FIX THIS LATER BECAUSE it will be passed in as command line argument
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // 2. Bind the socket to server's address
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // 3. Listen for incoming connections from client/s
    if (listen(serverSocket, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", SERVER_TCP_PORT);

    // 4. Accept and the server and client are now connected
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrSize);
    if (clientSocket == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    // 5. Receive JSON configuration data from the client
    char buffer[2048];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        perror("Error receiving data from client");
        close(clientSocket);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    // Null-terminate the received data
    buffer[bytesRead] = '\0';

    // Print the received JSON data (for debugging)
    printf("Received JSON data from client:\n%s\n", buffer);

    // Parse the JSON data
    json = cJSON_Parse(buffer);
    if (json == NULL) {
        perror("Error parsing JSON data");
        close(clientSocket);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    // STORING JSON FILE INTO STRUCT
    handleConfigData(json, serverConfig);

    // Clean up cJSON resources
    cJSON_Delete(json);

    // Close the client and server sockets
    close(clientSocket);
    close(serverSocket);

    printf("Configuration data received from the client.\n");
}


//---UDP CONNECTION---

// Function to recieve UDP packets
// void receiveUDPPackets(int numLowEntropyPackets, int numHighEntropyPackets) {
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

    // Debugging: Print the bound address and port
    printf("Bound to address: %s, port: %d\n", config.serverIPAddress, config.destinationPortUDP);

    // 1. read low entropy
    gettimeofday(&startTimeLowEntropy, NULL); // Record start time for low entropy

    for (int i = 0; i < config.numPackets; i++) {
        int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrSize);

        //set socket opt to do timeout
        //Other way is general timeout on train

        if (bytesRead <= 0) {
            perror("Error receiving low entropy data from client");
            break;
        }

        buffer[bytesRead] = '\0';
        //printf("Received low entropy packet: %s\n", buffer);
    }
    gettimeofday(&endTimeLowEntropy, NULL); // Record end time for low entropy


    printf("Received low entropy packets...\n");

    // 2. Wait for Inter-Measurement Time 
    sleep(config.interMeasurementTime); //drop to 5 seconds for testing. can put sleeps to make sure server is listening to client

    // 3. read high entropy
    gettimeofday(&startTimeHighEntropy, NULL); // Record start time for high entropy
    for (int i = 0; i < config.numPackets; i++) {
        int bytesRead = recvfrom(udpSocket, buffer, config.payload, 0, (struct sockaddr*)&clientAddr, &addrSize);
        // int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddr, &addrSize);
        if (bytesRead <= 0) {
            perror("Error receiving high entropy data from client");
            break;
        }

        buffer[bytesRead] = '\0';
        //printf("Received high entropy packet: %s\n", buffer);
    }
    gettimeofday(&endTimeHighEntropy, NULL); // Record end time for high entropy

    printf("UDP Packets recieved from client\n");

    close(udpSocket);

    // Calculate time differences
    double timeDifferenceLowEntropy = difftime(endTimeLowEntropy.tv_usec, startTimeLowEntropy.tv_usec);
    double timeDifferenceHighEntropy = difftime(endTimeHighEntropy.tv_usec, startTimeHighEntropy.tv_usec);

    if (fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy) > 100000.0) {
        printf("Compression detected!\n");
        // You can send this information to the client if needed
    } else {
        printf("No compression was detected\n");
    }
}


int main() {
    

    struct ServerConfig serverConfig; // Declare the server's configuration struct

    
    //receiveConfigFromClient();
    // Call the function to receive and parse the client's JSON configuration
    receiveConfigFromClient(&serverConfig);

    //print check:
    printf("Main: This Server IP Address: %s\n", serverConfig.serverIPAddress);
    printf("Main: Source Port UDP: %d\n", serverConfig.sourcePortUDP);
    printf("Main: Destination Port UDP: %d\n", serverConfig.destinationPortUDP);
    printf("Main: Destination Port TCP Head SYN: %d\n", serverConfig.destinationPortTCPHeadSYN);
    printf("Main: Destination Port TCP Tail SYN: %d\n", serverConfig.destinationPortTCPTailSYN);
    printf("Main: Port TCP Pre Probing: %d\n", serverConfig.portTCPPreProbing);
    printf("Main: Port TCP Post Probing: %d\n", serverConfig.portTCPPostProbing);
    printf("Main: UDP Payload: %d\n", serverConfig.payload);
    printf("Main: Intermeasurement time: %d\n", serverConfig.interMeasurementTime);
    printf("Main: Number of packets: %d\n", serverConfig.numPackets);
    printf("Main: Time to live: %d\n", serverConfig.timeToLive);

        // Debugging: Print the parsed server configuration
    printf("Parsed server configuration:\n");
    printf("Server IP Address: %s\n", serverConfig.serverIPAddress);
    printf("Source Port UDP: %d\n", serverConfig.sourcePortUDP);

    // recieve
    //receiveUDPPackets(10, 10);  // Example: 10 low entropy and 10 high entropy packets
    receiveUDPPackets(serverConfig);

    return 0;
}

// //gcc -o server server_pt_1.c -lcjson -I/usr/local/opt/cjson/include -L/usr/local/opt/cjson/lib