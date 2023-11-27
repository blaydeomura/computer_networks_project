# Contributors
Blayde Omura 
*note* standalone.c application contains open source code from P.D. Buchan (cited)

# Networks Compression Detection Project
- Part 1: client_pt_1.c and server_pt_2.c - client server detection program
- Part 2: standalone.c - standalone compression detection program

# Instructions how to build and run programs
- Part 1:
	1) Ensure you have files: 
		- cJSON.h 
		- cJSON.c 
		- client_pt_1.c
		- server_pt_2.c
		- config.json
	2) Capture packets through wireshark
		- "sudo wireshark"
		- * enter admin password
		- input packet filter "ip.addr==192.168.64.2 && ip.addr==192.168.64.3"
		- * press start button blue button 
	3) Start up server 
		- "gcc server_pt_1.c -o server"
		- "./<name to run server> 7777"
		- *your server is ready and will hang until client is ran
	4) Start up client second
		- "gcc client_pt_1.c -o client"
		- "./client config.json"
		- *your client will start up the program
	5) The program will execute and your results will be displayed in the output
	   of your client
	6) Analyze wireshark results
		- * Press stop button
		- Ensure packet filter is on
		- Analyze results

- Part 2:
	1) Ensure you have the files:
		- cJSON.h
		- cJSON.c
		- standalone.c
		- config.json
        2) Capture packets through wireshark
                - "sudo wireshark"
                - * enter admin password
                - input packet filter "ip.addr==192.168.64.2 && ip.addr==192.168.64.3"
                - * press start button blue button
	3) Run program through client
		- "gcc standalone.c -o standalone"
		- "sudo ./standalone config.json"
	4) Your program executes and outputs results
        5) Analyze wireshark results
                - * Press stop button
                - Ensure packet filter is on
                - Analyze results


# Incomplete features
- I have implemented all features correctly to my knowledge.


		
