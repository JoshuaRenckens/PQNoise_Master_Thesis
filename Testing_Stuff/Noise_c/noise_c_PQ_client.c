#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/*static uint8_t const psk[32] = {
    0x4d, 0xfe, 0xb6, 0xba, 0x4a, 0x7b, 0xcd, 0xf0,
    0x58, 0x1d, 0x9c, 0x31, 0x53, 0x64, 0xb5, 0x03,
    0xd9, 0xe1, 0x42, 0x41, 0xb1, 0xae, 0xf4, 0x04,
    0x56, 0x0d, 0x32, 0xc0, 0xb6, 0xe3, 0xd9, 0x56
};*/

uint64_t start2, stop2;

int64_t get_cpucycles()
{ // Access system counter for benchmarking
  unsigned int hi, lo;
  
  //asm("cpuid");
  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);
}

int comp(const void* elem1, const void* elem2){
	int val1 = *((int*)elem1);
	int val2 = *((int*)elem2);
	return (val1 > val2) - (val1 < val2);
}

// Size is max message length + 2
static uint8_t message[65535 + 2];
static int test_number = 1000;
uint64_t start2, stop2, start3, stop3;

int main(int argc, char *argv[])
{
	NoiseDHState *dh;
	NoiseHandshakeState *handshake;
	int err;
	int action;
	int last_action;
	int socket_desc;
	struct sockaddr_in server;
	NoiseBuffer mbuf;
	size_t message_size, received, full_size;
	
	uint64_t total_time = 0;
	uint64_t max = 0;
	uint64_t min = 10000000000;
	uint64_t current = 0;
	uint64_t results[1000];
	
	/*For NK the client is in possession of the servers public key. Uses the hardcoded keys*/
	/*dh = noise_handshakestate_get_remote_public_key_dh(handshake);
	err = noise_dhstate_set_public_key(dh, psk, sizeof(psk));
	if (err != NOISE_ERROR_NONE) {
		noise_perror("set server public key", err);
		return 1;
	}*/


	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("192.168.178.105");
	server.sin_port = htons( 8888 );

	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("connect error");
		return 1;
	}

	puts("Connected\n");
	
	
	for(int i = 0; i <= test_number; i++){
	
		/*Initialize the handshake state with the protocol and the role*/
		err = noise_handshakestate_new_by_name(&handshake,  "Noise_NK_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_INITIATOR);
		if (err != NOISE_ERROR_NONE) {
			noise_perror("Noise_pqNK_Kyber512_ChaChaPoly_BLAKE2s", err);
			return 1;
		}
		
		/*Create own static key*/
		/*dh = noise_handshakestate_get_local_keypair_dh(handshake);
		//start2 = get_cpucycles();
		err = noise_dhstate_generate_keypair(dh);
		//stop2 = get_cpucycles();
		//printf("Time taken to create static key: %ld cycles.\n", stop2 - start2);
		if (err != NOISE_ERROR_NONE) {
		    noise_perror("Generate key", err);
		    return 1;
		}*/
		
		/*Send server own static public key*/
		/*err = noise_dhstate_get_public_key(dh, message, 32);
		if (err != NOISE_ERROR_NONE) {
		    noise_perror("Get public key", err);
		    return 1;
		}
		int sent = send(socket_desc, message, 32, 0);
		if (sent < 0) {
		    	puts("Error on receiving the public key");
		}*/
		
		// To avoid the client sending two messages back to back, needed for KX and KN handshakes
		/*message_size = recv(socket_desc, message , sizeof(message) , 0);
		if(message_size != 1){
			puts("Error on 1 bit receive, client");
		    	break;
		}*/
		
		/*Receive the servers public key, cause I'm not hardcoding an 800 byte key, and set the remote public key. Used for */	
		int rec = recv(socket_desc, message, 32, 0);
		if (rec < 0) {
		    	puts("Error on receiving the public key");
		}
		dh = noise_handshakestate_get_remote_public_key_dh(handshake);
		err = noise_dhstate_set_public_key(dh, message, 32);
		if (err != NOISE_ERROR_NONE) {
		    	noise_perror("set server public key", err);
			return 1;
		}
		
		/*Start the handshake*/
		int ok = 1;
		puts("Handshake starting");
		err = noise_handshakestate_start(handshake);
		if (err != NOISE_ERROR_NONE) {
		    noise_perror("start handshake", err);
		    ok = 0;
		}
			    

		/* Run the handshake until we run out of things to read or write */
		start2 = get_cpucycles();
		while (ok) {
			last_action = action;
			action = noise_handshakestate_get_action(handshake);
			if (action == NOISE_ACTION_WRITE_MESSAGE) {
			    /* Write the next handshake message with a zero-length payload */
			    noise_buffer_set_output(mbuf, message + 2 , sizeof(message) - 2);
			    
			    start3 = get_cpucycles();
			    
			    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
			    
			    stop3 = get_cpucycles();
			    printf("Time taken to create next message: %ld cycles.\n", stop3 - start3);
			    
			    if (err != NOISE_ERROR_NONE) {
				noise_perror("write handshake", err);
				printf("Error, %d\n", err);
				ok = 0;
				break;
			    }
			    message[0] = (uint8_t)(mbuf.size >> 8);
			    message[1] = (uint8_t)mbuf.size;
			    
			    full_size = mbuf.size + 2;
			    received = 0;
			    while(full_size > 0){
			    	if(full_size < 1448){
				    if (send(socket_desc , message + received, full_size , 0) < 0) {
				    	puts("Error on send, client");
					ok = 0;
					break;
				    }
				    //printf("Message size: %ld, Full size: %ld, Sent previously: %ld \n", full_size, mbuf.size, received);
				    full_size = 0;
				} else {
				    if (send(socket_desc , message + received , 1448 , 0) < 0) {
				    	puts("Error on send, client");
					ok = 0;
					break;
				    }
				    //printf("Message size: %d, Full size: %ld, Sent previously: %ld \n", 1448, mbuf.size, received);
				    full_size -= 1448;
				    received += 1448;
				}
			    }
			    
			} else if (action == NOISE_ACTION_READ_MESSAGE) {
			    /* Read the next handshake message and discard the payload */
			    full_size = 1;
			    received = 0;
			    while(full_size > received){
				    message_size = recv(socket_desc, message + received , sizeof(message) - received , 0);
				    
				    if (!message_size) {
				    	puts("Error on receive, client");
					ok = 0;
					break;
				    }
				    if (message_size < 0) {
				    	puts("Error on receive, client");
					ok = 0;
					break;
				    }
				    if(full_size == 1){
				    	full_size = (message[0]<<8) + message[1];
				    }
				    received += message_size;
				    //printf("Message size: %ld, Full size: %ld, Received: %ld \n", message_size, full_size, received);
			    }
			    noise_buffer_set_input(mbuf, message + 2 , received - 2);
			    
			    start3 = get_cpucycles();
			    
			    err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
			    
			    stop3 = get_cpucycles();
			    //printf("Read, buffer size: %ld\n", mbuf.size);
			    //printf("Received: %ld\n", received);
			    printf("Time taken to process the message: %ld cycles.\n", stop3 - start3);
			    
			    if (err != NOISE_ERROR_NONE) {
				noise_perror("read handshake", err);
				ok = 0;
				break;
			    }
			} else {
			    /* Either the handshake has finished or it has failed */
			    break;
			}
		}
		stop2 = get_cpucycles();
		current = stop2 - start2;
		// One run to warm the cache where we won't include the time
		if(i != 0){
			total_time += current;
			
			if(current > max){
				max = current;
			}
			
			if(current < min){
				min = current;
			}
			results[i-1] = current;
		}
		printf("\nTime taken by run %d: %ld cycles.\n", i, current);
		printf("Current total time: %ld cycles.\n", total_time);
		
		if(ok == 0){
			puts("Handshake failed\n");
		}
		
		if (last_action == NOISE_ACTION_WRITE_MESSAGE){
			message_size = recv(socket_desc, message , sizeof(message) , 0);
			if(message_size != 1){
				puts("Error on final receive, client");
				ok = 0;
			    	break;
			}
			//puts("Final receive done, client\n\n");
		}
		
		if (last_action == NOISE_ACTION_READ_MESSAGE) {
			message[0] = 0;
			if (send(socket_desc , message , 1 , 0) < 0) {
				puts("Error on final send, server");
				ok = 0;
				break;
			}
			//puts("Final send done, server\n\n");
		}
		
	}
	qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
	printf("Average time taken by the handshakes: %ld cycles.\n", total_time/test_number);
	printf("Median time taken by the handshakes: %ld cycles.\n", results[500]);
	printf("Maximum time taken by the handshakes: %ld cycles.\n", max);
	printf("Minimum time taken by the handshakes: %ld cycles.\n", min);
	close(socket_desc);

	return 0;
}
