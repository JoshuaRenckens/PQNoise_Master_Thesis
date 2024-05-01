#include <benchmark/benchmark.h>
#include <sys/socket.h>
#include <string>
#include <cstring>
#include <iostream>

extern "C" {

#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

	static uint8_t message[65535 + 2];
	
	NoiseHandshakeState* iteration_setup(char id[]) {
		NoiseHandshakeState *handshake;
		int err;
		err = noise_handshakestate_new_by_name(&handshake,  id, NOISE_ROLE_RESPONDER);
	 	if (err != NOISE_ERROR_NONE) {
			noise_perror("Noise_pqNK_Kyber512_ChaChaPoly_BLAKE2s", err);
			return NULL;
		} 
		
		// Get the handshake state ready to start
		err = noise_handshakestate_start(handshake);
		if (err != NOISE_ERROR_NONE) {
		    noise_perror("start handshake", err);
		    return NULL;
		}
		return handshake;
	}
	
	int noise_handshake(NoiseHandshakeState* handshake, int new_socket){
		int err, action, last_action;
		NoiseBuffer mbuf;
		size_t message_size, received, full_size;
		int ok = 1;
		
		while (ok) {
			last_action = action;
			action = noise_handshakestate_get_action(handshake);
			if (action == NOISE_ACTION_WRITE_MESSAGE) {
			    /* Write the next handshake message with a zero-length payload */
			    noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);

			    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
			   
			    
			    if (err != NOISE_ERROR_NONE) {
				noise_perror("write handshake", err);
				printf("Error, %d\n", err);
				ok = 0;
				break;
			    }
			    message[0] = (uint8_t)(mbuf.size >> 8);
			    message[1] = (uint8_t)mbuf.size;
			    //printf("Write, buffer size: %ld\n", mbuf.size);
			    
			    full_size = mbuf.size + 2;
			    received = 0;
			    while(full_size > 0){
			    	if(full_size < 1448){
				    if (send(new_socket , message + received , full_size , 0) < 0) {
				    	puts("Error on send, server");
					ok = 0;
					break;
				    }
				    //printf("Message_size: %ld, Full size: %ld, Sent previously: %ld\n", full_size, mbuf.size, received);
				    full_size = 0;
				} else {
				    if (send(new_socket , message + received , 1448 , 0) < 0) {
				    	puts("Error on send, server");
					ok = 0;
					break;
				    }
				    //printf("Message_size: %d, Full size: %ld, Sent previously: %ld\n", 1448, mbuf.size, received);
				    full_size -= 1448;
				    received += 1448;
				}
			    }
			} else if (action == NOISE_ACTION_READ_MESSAGE) {
			    /* Read the next handshake message and discard the payload */
			    full_size = 1;
			    received = 0;
			    while(full_size > received){
				    message_size = recv(new_socket, message + received , sizeof(message) - received , 0);
				    if (!message_size) {
				    	puts("Error on receive, server");
					ok = 0;
					break;
				    }
				    if (message_size < 0) {
				    	puts("Error on receive, client");
					ok = 0;
					break;
				    }
				    if(full_size == 1){
				    	full_size = (message[0] << 8) + message[1];
				    }
				    received += message_size;
				    //printf("Message_size: %ld, Full size: %ld, Received: %ld\n", message_size, full_size, received);
			    }
			    noise_buffer_set_input(mbuf, message + 2, received - 2);
			    
			    err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
			    //printf("Read, buffer size: %ld\n", mbuf.size);
			    //printf("Received: %ld\n", received);
			    
			    if (err != NOISE_ERROR_NONE) {
			    	//printf("Error value: %d \n", err);
				noise_perror("read handshake", err);
				ok = 0;
				break;
			    }
			} else {
			    /* Either the handshake has finished or it has failed */
			    break;
			}
		}
		return last_action;
	}
}

static void BM_NoiseHandshake(benchmark::State& state) {
	int socket_desc , new_socket, c;
    	struct sockaddr_in server , client;
    	NoiseBuffer mbuf;
    	size_t message_size, received, full_size;
	
	std::string s = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
	char* id = new char [s.length() + 1];
	strcpy(id, s.c_str());
	
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		//std::cout << "Could not create socket";
	}
	    
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8888 );
	
	    
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		//std::cout << "bind failed";
		return ;
	}
	
	std::cout << "Here";
	    
	//Listen
	listen(socket_desc , 3);
	    
	//Accept incoming connection
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	std::cout << "Here";
	
	// Where we measure. Because there is setup that has to be done every loop we start by pausing, doing the setup, then resuming.
	for (auto _ : state){
		// Pause timing and resume timing together give an overhead of ~200 ns every time they are used.
		state.PauseTiming();
		std::cout << "Here";
		NoiseHandshakeState *handshake = iteration_setup(id);
    		state.ResumeTiming();
    		
    		noise_handshake(handshake, new_socket);
	}
		
}

// Register the function as a benchmark
BENCHMARK(BM_NoiseHandshake);

BENCHMARK_MAIN();
