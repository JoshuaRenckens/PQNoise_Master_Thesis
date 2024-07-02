#include <limits.h>
#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000


// Size is max Noise message length + 2
static uint8_t message[65535 + 2];
static int test_number = 1000;
static char extra_front[4][5] = {"KN", "pqKN", "KX", "pqKX"};
static char send_key[6][5] = {"KN", "KX", "KK", "pqKN", "pqKX", "pqKK"};
static char to_test[24][5] = {"NN", "pqNN", "NX", "pqNX", "NK", "pqNK", "XN", "pqXN", "XX", "pqXX", "XK", "pqXK",
				    "KN", "pqKN", "KX", "pqKX", "KK", "pqKK", "IN", "pqIN", "IX", "pqIX", "IK", "pqIK"};
static const char to_test_full_name[24][40] = {"Noise_NN_25519_ChaChaPoly_BLAKE2s", "Noise_pqNN_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_NX_25519_ChaChaPoly_BLAKE2s", "Noise_pqNX_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_NK_25519_ChaChaPoly_BLAKE2s", "Noise_pqNK_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_XN_25519_ChaChaPoly_BLAKE2s", "Noise_pqXN_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_XX_25519_ChaChaPoly_BLAKE2s", "Noise_pqXX_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_XK_25519_ChaChaPoly_BLAKE2s", "Noise_pqXK_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_KN_25519_ChaChaPoly_BLAKE2s", "Noise_pqKN_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_KX_25519_ChaChaPoly_BLAKE2s", "Noise_pqKX_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_KK_25519_ChaChaPoly_BLAKE2s", "Noise_pqKK_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_IN_25519_ChaChaPoly_BLAKE2s", "Noise_pqIN_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_IX_25519_ChaChaPoly_BLAKE2s", "Noise_pqIX_Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_IK_25519_ChaChaPoly_BLAKE2s", "Noise_pqIK_Kyber512_ChaChaPoly_BLAKE2s"};

/*Access system counter for benchmarking*/
int64_t get_cpucycles()
{ 
#if defined(__GNUC__) && defined(__ARM_ARCH_7A__)
	// Case for the board
        uint32_t r = 0;
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(r) );
        return r;
#else
	// Case for my laptop
	unsigned int hi, lo;
  
  	asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  	return ((int64_t)lo) | (((int64_t)hi) << 32);
#endif
}

int comp(const void* elem1, const void* elem2){
	int val1 = *((int*)elem1);
	int val2 = *((int*)elem2);
	return (val1 > val2) - (val1 < val2);
}

int max(int a, int b){
	if(a > b){
		return a;
	} else {
		return b;
	}
}

/*Check if the current pattern is in one of the above lists. Need to check whether we have to send a static key, or also have to receive a byte to space the clients messages. The byte thing is necessary for the "KN" and "KX" pattern as the client would send his static key and afterwards the first actual handshake message and for some reason sending those two messages in a row messes up the second message.*/
int in_list(int place, int index){
	char* elem = to_test[index];
	int res = 0;
	if(place == 0){
		for(int i = 0; i < 4; i++){
			res = max(!strcmp(extra_front[i], elem), res);
		}
	} else if (place == 1){
		for(int i = 0; i < 6; i++){
			res = max(!strcmp(send_key[i], elem), res);
		}
	}
	return res;
}


int main(int argc, char *argv[])
{
	NoiseDHState *dh;
	NoiseHandshakeState *handshake;
	int err, action, key_size, socket_desc;
	struct sockaddr_in server;
	NoiseBuffer mbuf;
	size_t message_size, received, full_size;
	
	uint64_t total_time, total_time_comp, max, min, current;
	uint64_t results[test_number];
	double handshake_times_ms[test_number];
	uint64_t start2, stop2, start3, stop3;
	
	struct timespec start, stop;
	
	/*Initialize socket*/
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("10.0.0.1");
	server.sin_port = htons( 8888 );
	
	// Go through the list of handshake names and run them all.
    	for(int k = 0; k < 24; k++){
	    	// Set the correct key size, the regular handshakes are at even positions in the list while the pq ones are not.
		if(k%2 == 0){
			key_size = 32;
		} else {
		    	key_size = 800;
		}
	    	
	    	total_time = 0;
		total_time_comp = 0;
		max = 0;
		min = INT_MAX;
		current = 0;
	    
	    	//printf("\nStarting runs for %s handshake.\n", to_test[k]);
	    	// Run the handshake test_number of times
	    	
		for(int i = 0; i <= test_number; i++){
		
			/*Create socket*/
			socket_desc = socket(AF_INET , SOCK_STREAM , 0);
			if (socket_desc == -1)
			{
				printf("Could not create socket");
			}
			
			/*Connect to server*/
			if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
			{
				puts("connect error");
				return 1;
			}

			/*Preparation for the handshake*/
			
			/*Initialize the handshake state with the protocol and the role*/
			err = noise_handshakestate_new_by_name(&handshake,  to_test_full_name[k], NOISE_ROLE_INITIATOR);
			if (err != NOISE_ERROR_NONE) {
				noise_perror(to_test_full_name[k], err);
				return 1;
			}
			
			/*Create own static key*/
			if (noise_handshakestate_needs_local_keypair(handshake)){
				dh = noise_handshakestate_get_local_keypair_dh(handshake);
				//start2 = get_cpucycles();
				err = noise_dhstate_generate_keypair(dh);
				//stop2 = get_cpucycles();
				//printf("Time taken to create static key: %ld cycles.\n", stop2 - start2);
				if (err != NOISE_ERROR_NONE) {
				    noise_perror("Generate key", err);
				    return 1;
				}
			}
			
			/*Send server own static public key*/
			if(in_list(1, k)){
				err = noise_dhstate_get_public_key(dh, message, key_size);
				if (err != NOISE_ERROR_NONE) {
				    noise_perror("Get public key", err);
				    return 1;
				}
				int sent = send(socket_desc, message, key_size, 0);
				if (sent < 0) {
				    	puts("Error on receiving the public key");
				}
			}
			
			/*To avoid the client sending two messages back to back, needed for KX and KN handshakes*/
			if(in_list(0, k)){
				message_size = recv(socket_desc, message , sizeof(message) , 0);
				if(message_size != 1){
					puts("Error on 1 bit receive, client");
				    	break;
				}
			}
			
			/*Receive the servers public key, cause I'm not hardcoding an 800 byte key, and set the remote public key. Used for */	
			if (noise_handshakestate_needs_remote_public_key(handshake)){
				int rec = recv(socket_desc, message, key_size, 0);
				if (rec < 0) {
				    	puts("Error on receiving the public key");
				}
				dh = noise_handshakestate_get_remote_public_key_dh(handshake);
				err = noise_dhstate_set_public_key(dh, message, key_size);
				if (err != NOISE_ERROR_NONE) {
				    	noise_perror("set server public key", err);
					return 1;
				}
			}
			
			
			/*Start the handshake*/
			
			int ok = 1;
			//puts("Handshake starting");
			err = noise_handshakestate_start(handshake);
			if (err != NOISE_ERROR_NONE) {
			    noise_perror("start handshake", err);
			    ok = 0;
			}
				    

			/* Run the handshake until we run out of things to read or write */
			clock_gettime(CLOCK_MONOTONIC_RAW, &start);
			start2 = get_cpucycles();
			while (ok) {
				action = noise_handshakestate_get_action(handshake);
				if (action == NOISE_ACTION_WRITE_MESSAGE) {
				    /* Write the next handshake message with a zero-length payload */
				    noise_buffer_set_output(mbuf, message + 2 , sizeof(message) - 2);
				    
				    start3 = get_cpucycles();
				    
				    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
				    
				    stop3 = get_cpucycles();
				    //printf("Time taken to create next message: %ld cycles.\n", stop3 - start3);
				    current = stop3 - start3;
				    
				    // In case the cpu cycle counter overflowed, happens fairly regularly on the board.
				    if(current > INT_MAX/2){
				    	current = ~current;
				    }
			
				    total_time_comp += current;
				    
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
				    //printf("Time taken to process the message: %ld cycles.\n", stop3 - start3);
				    current = stop3 - start3;
				    
				    // In case the cpu cycle counter overflowed, happens fairly regularly on the board.
				    if(current > INT_MAX/2){
				    	current = ~current;
				    }
			
				    total_time_comp += current;
				    
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
			clock_gettime(CLOCK_MONOTONIC_RAW, &stop);
			
			current = stop2 - start2;
			
			// In case the cpu cycle counter overflowed, happens fairly regularly on the board.
			if(current > INT_MAX/2){
				current = ~current;
			}
			
			/* One run warmup run where we won't include the time */
			if(i != 0){
				total_time += current;
				
				if(current > max){
					max = current;
				}
				
				if(current < min){
					min = current;
				}
				results[i-1] = current;
				handshake_times_ms[i-1] = ((stop.tv_sec - start.tv_sec) * MS_IN_S) + ((stop.tv_nsec - start.tv_nsec) / NS_IN_MS);
			}
			//printf("\nTime taken by run %d: %ld cycles.\n", i, current);
			//printf("Current total time: %ld cycles.\n", total_time);
			
			if(ok == 0){
				puts("Handshake failed\n");
			}
			
			
			close(socket_desc);
			
		}
		float comp_percent = ((float) total_time_comp) / ((float) total_time) * 100.0;
		qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
		/*Print in a format to copy paste into latex tables, in order of: what pattern we're at, average time, median time, max time, minimum time, average computation 
		  time and lastly the percent of the average time that the computational time takes up*/
		if(k % 2 == 0){
			printf("\\hline\\hline \n");
		}
		printf("%s & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f \\\\ \n", to_test[k], (total_time/test_number)/1000000.0, results[test_number/2]/1000000.0, max/1000000.0, min/1000000.0, (total_time_comp/test_number)/1000000.0, comp_percent, handshake_times_ms[test_number/2]);
		if(k % 2 == 0){
			printf("\\hline \n");
		}
		//Print in more human readable format
		/*printf("Average time taken by the handshakes: %ld cycles.\n", total_time/test_number);
		printf("Average time taken for the computations: %ld cycles.\n", total_time_comp/test_number);
        	printf("On average %5.2f percent of the total time is computation.\n\n", comp_percent);
		printf("Median time taken by the handshakes: %ld cycles.\n", results[500]);
		printf("Maximum time taken by the handshakes: %ld cycles.\n", max);
		printf("Minimum time taken by the handshakes: %ld cycles.\n", min);*/
	}

	return 0;
}
