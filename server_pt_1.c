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
void receiveConfigFromClient(struct ServerConfig* serverConfig, int serverPort) {
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
    serverAddr.sin_port = htons(serverPort);    
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



/*
//---UDP CONNECTION---
void sendCompressionStatusToClient(struct ServerConfig config, int compressionDetected) {

    int postProbingSocket;
    struct sockaddr_in serverAddr;

    // 1. Create a socket
    postProbingSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (postProbingSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // 2. Initialize server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.portTCPPreProbing);

    serverAddr.sin_addr.s_addr = inet_addr("192.168.64.2"); //CHANGED

    // 3. Connect to the server
    if (connect(postProbingSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        printf("error connecting to server\n");
        exit(EXIT_FAILURE);
    }
    // Send compression detection status to the client
    send(postProbingSocket, &compressionDetected, sizeof(int), 0);

    // Close the socket
    close(postProbingSocket);


}
*/


/*
// Function to establish a TCP connection with the client
int establishTCPConnection(struct ServerConfig config) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize = sizeof(clientAddr);

    // 1. Server creates socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }


    // Set SO_REUSEADDR option
    int reuse = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        perror("Error setting SO_REUSEADDR option");
        exit(EXIT_FAILURE);
    }


    // Initialize server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.portTCPPostProbing);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // 2. Bind the socket to the server's address
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // 3. Listen for incoming connections from the client
    if (listen(serverSocket, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for TCP connection on port %d...\n", config.portTCPPostProbing);

    // 4. Accept the client connection
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrSize);
    if (clientSocket == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    // 5. Send some data to the client (you can customize this part)
    const char* message = "Connection established. Hello from server!";
    send(clientSocket, message, strlen(message), 0);

    // 6. Close the sockets
    close(clientSocket);
    close(serverSocket);

    return 0;
}
*/







// Function to recieve UDP packets
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

    printf("High entropy packets recieved from client\n");

    close(udpSocket);




    int serverSocket1, clientSocket1;
    struct sockaddr_in serverAddr1, clientAddr1;
    //socklen_t addrSize = sizeof(clientAddr1);

    // 1. Server creates socket
    serverSocket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket1 == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }


    // Set SO_REUSEADDR option
    int reuse = 1;
    if (setsockopt(serverSocket1, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        perror("Error setting SO_REUSEADDR option");
        exit(EXIT_FAILURE);
    }


    // Initialize server address structure
    memset(&serverAddr1, 0, sizeof(serverAddr1));
    serverAddr1.sin_family = AF_INET;
    serverAddr1.sin_port = htons(config.portTCPPostProbing);
    serverAddr1.sin_addr.s_addr = INADDR_ANY;

    // 2. Bind the socket to the server's address
    if (bind(serverSocket1, (struct sockaddr*)&serverAddr1, sizeof(serverAddr1)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // 3. Listen for incoming connections from the client
    if (listen(serverSocket1, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for TCP connection on port %d...\n", config.portTCPPostProbing);

    // 4. Accept the client connection
    clientSocket1 = accept(serverSocket1, (struct sockaddr*)&clientAddr1, &addrSize);
    if (clientSocket1 == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    // 5. Send some data to the client (you can customize this part)
   // const char* message = "Connection established. Hello from server!";
    //send(clientSocket1, message, strlen(message), 0);

    // Now you can use tcpClientSocket to send/receive data over the established TCP connection
    double timeDifferenceLowEntropy = difftime(endTimeLowEntropy.tv_usec, startTimeLowEntropy.tv_usec);
    double timeDifferenceHighEntropy = difftime(endTimeHighEntropy.tv_usec, startTimeHighEntropy.tv_usec);

    int compressionDetected = (fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy) > 100000.0);
    
    printf("Time difference: %f\n", fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy));
    printf("Compression detected: %d\n", compressionDetected);

    
    if (send(clientSocket1, &compressionDetected, sizeof(int), 0) == -1) {
	    perror("Error sending compression detected boolean: \n");
	    exit(EXIT_FAILURE);
    }

    //ERROR CHECK HERE

    // 6. Close the sockets
    close(clientSocket1);
    close(serverSocket1);








/*
    // Now you can use tcpClientSocket to send/receive data over the established TCP connection
    // Now you can use tcpClientSocket to send/receive data over the established TCP connection
    double timeDifferenceLowEntropy = difftime(endTimeLowEntropy.tv_usec, startTimeLowEntropy.tv_usec);
    double timeDifferenceHighEntropy = difftime(endTimeHighEntropy.tv_usec, startTimeHighEntropy.tv_usec);

    int compressionDetected = (fabs(timeDifferenceHighEntropy - timeDifferenceLowEntropy) > 100000.0);

    printf("Compression detected: %d\n", compressionDetected);

//    send(tcpClientSocket, &compressionDetected, sizeof(int), 0);

*/
    // Close the TCP sockets
}



int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int serverPort = atoi(argv[1]); // Convert the port number from string to integer
 

    struct ServerConfig serverConfig; // Declare the server's configuration struct
    
    // Call the function to receive and parse the client's JSON configuration
    receiveConfigFromClient(&serverConfig, serverPort);

    receiveUDPPackets(serverConfig);

  //  establishTCPConnection(serverConfig);

    return 0;
}

