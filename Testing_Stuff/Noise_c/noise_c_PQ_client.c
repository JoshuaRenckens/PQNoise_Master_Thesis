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

/*Access system counter for benchmarking*/
int64_t get_cpucycles()
{ 
#if defined(__GNUC__) && defined(__ARM_ARCH_7A__)
	// Case for the board
        uint32_t r = 0;
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(r) );
        return r;
#else
	// Case for my laptop (Intel cpu)
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

int comp2(const void* elem1, const void* elem2){
	double val1 = *((double*)elem1);
	double val2 = *((double*)elem2);
	return (val1 > val2) - (val1 < val2);
}

int max(int a, int b){
	if(a > b){
		return a;
	} else {
		return b;
	}
}

int load_key(char *file, uint8_t *key, int size){
	FILE *fp;
	fp = fopen(file, "r");
		
	if(fp == NULL){
		puts("Error opening file");
		return 1;
	}
	
	size_t read = fread(key, 1, size, fp);
	if(read != size){
		puts("Wrong amount of bytes read");
		return 1;
	}
	
	fclose(fp);
	return 0;
}


int main(int argc, char *argv[])
{
	if(argc != 2){
		puts("Wrong amount of arguments, expected 1.");
		return 1;
	}
	
	NoiseDHState *dh;
	NoiseHandshakeState *handshake;
	int err, action, key_size, socket_desc;
	struct sockaddr_in server;
	NoiseBuffer mbuf;
	size_t message_size, received, full_size;
	
	uint64_t total_time, total_time_comp, max, min, current;
	uint64_t results[test_number];
	double handshake_times_ms[test_number], overall_ms;
	uint64_t start2, stop2, start3, stop3;
	
	char to_test_full[2][40];
	snprintf(to_test_full[0], sizeof(to_test_full[0]), "Noise_%s_25519_ChaChaPoly_BLAKE2s", argv[1]);
	snprintf(to_test_full[1], sizeof(to_test_full[1]), "Noise_pq%s_Kyber512_ChaChaPoly_BLAKE2s", argv[1]);
	
	char to_test[2][5];
	snprintf(to_test[0], sizeof(to_test[0]), "%s", argv[1]);
	snprintf(to_test[1], sizeof(to_test[1]), "pq%s", argv[1]);
	
	//Load all of the keys we will need to run every pattern
    	uint8_t client_private[32];
    	uint8_t client_public[32];
    	uint8_t server_public[32];
    	uint8_t client_private_pq[1632];
    	uint8_t client_public_pq[800];
    	uint8_t server_public_pq[800];
    	
    	load_key("./Keys/client_priv.txt", client_private, 32);
    	load_key("./Keys/client_pub.txt", client_public, 32);
    	load_key("./Keys/server_pub.txt", server_public, 32);
    	load_key("./Keys/client_priv_pq.txt", client_private_pq, 1632);
    	load_key("./Keys/client_pub_pq.txt", client_public_pq, 800);
    	load_key("./Keys/server_pub_pq.txt", server_public_pq, 800);
	
	struct timespec start, stop;
	
	//Initialize socket
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("10.0.0.1");
	server.sin_port = htons( 8888 );
	
	
	// Go through the list of handshake names and run them all.
    	for(int k = 0; k < 2; k++){
	    	// Set the correct key size, the regular handshakes are at even positions in the list while the pq ones are not.
		if(k%2 == 0){
			key_size = 32;
		} else {
		    	key_size = 800;
		}
	    	
	    	total_time = 0;
		total_time_comp = 0;
		overall_ms = 0;
		max = 0;
		min = INT_MAX;
		current = 0;
	    
	    	//printf("\nStarting runs for %s handshake.\n", to_test[k]);
	    	// Run the handshake test_number of times
	    	
		for(int i = 0; i <= test_number; i++){
	
			//Create socket
			socket_desc = socket(AF_INET , SOCK_STREAM , 0);
			if (socket_desc == -1)
			{
				printf("Could not create socket");
			}

			//Preparation for the handshake
			
			//Initialize the handshake state with the protocol and the role
			err = noise_handshakestate_new_by_name(&handshake,  to_test_full[k], NOISE_ROLE_INITIATOR);
			if (err != NOISE_ERROR_NONE) {
				noise_perror(to_test_full[k], err);
				return 1;
			}
			
			//Set own static keypair
			if (noise_handshakestate_needs_local_keypair(handshake)){
				dh = noise_handshakestate_get_local_keypair_dh(handshake);
				if(key_size == 32){
					err = noise_dhstate_set_keypair(dh, client_private, key_size, client_public, key_size);
				} else {
					err = noise_dhstate_set_keypair(dh, client_private_pq, 1632, client_public_pq, key_size);
				}
				
				if (err != NOISE_ERROR_NONE) {
				    noise_perror("Generate key", err);
				    return 1;
				}
			}
			
			//Set the remote public key.	
			if (noise_handshakestate_needs_remote_public_key(handshake)){
				dh = noise_handshakestate_get_remote_public_key_dh(handshake);
				
				if(key_size == 32){
					err = noise_dhstate_set_public_key(dh, server_public, key_size);
				} else {
					err = noise_dhstate_set_public_key(dh, server_public_pq, key_size);
				}
				
				if (err != NOISE_ERROR_NONE) {
				    	noise_perror("set server public key", err);
					return 1;
				}
			}
			
			
			//Start the handshake
			clock_gettime(CLOCK_MONOTONIC_RAW, &start);
			start2 = get_cpucycles();
			
			//Connect to server
			if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
			{
				puts("connect error");
				return 1;
			}
			
			int ok = 1;
			//puts("Handshake starting");
			err = noise_handshakestate_start(handshake);
			if (err != NOISE_ERROR_NONE) {
			    noise_perror("start handshake", err);
			    ok = 0;
			}
				    

			// Run the handshake until we run out of things to read or write 
			while (ok) {
				action = noise_handshakestate_get_action(handshake);
				if (action == NOISE_ACTION_WRITE_MESSAGE) {
				
				    // Write the next handshake message with a zero-length payload 
				    noise_buffer_set_output(mbuf, message + 2 , sizeof(message) - 2);
				    
				    start3 = get_cpucycles();
				    
				    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
				    
				    stop3 = get_cpucycles();
				    //printf("Time taken to create next message: %ld cycles.\n", stop3 - start3);
				    
				    if(start3 > stop3){
				    	// In case the cpu cycle counter overflowed, happens fairly regularly on the board.
				    	current = (stop3 + UINT_MAX) - start3;
				    } else {
				    	// Regular case
				    	current = stop3 - start3;
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
				    
				    if(start3 > stop3){
				    	// In case the cpu cycle counter overflowed, happens fairly regularly on the board.
				    	current = (stop3 + UINT_MAX) - start3;
				    } else {
				    	// Regular case
				    	current = stop3 - start3;
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
			
			close(socket_desc);
			
			if(start2 > stop2){
			    	// In case the cpu cycle counter overflowed, happens fairly regularly on the board.
			    	current = (stop2 + UINT_MAX) - start2;
			} else {
			    	// Regular case
			    	current = stop2 - start2;
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
				overall_ms += handshake_times_ms[i-1];
			}
			//printf("\nTime taken by run %d: %ld cycles.\n", i, current);
			//printf("Current total time: %ld cycles.\n", total_time);
			
			if(ok == 0){
				puts("Handshake failed\n");
			}
			
			
			
		}
		float comp_percent = ((float) total_time_comp) / ((float) total_time) * 100.0;
		qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
		qsort(handshake_times_ms, sizeof(handshake_times_ms)/sizeof(*handshake_times_ms), sizeof(*handshake_times_ms), comp2);
		/*Print in a format to copy paste into latex tables, in order of: what pattern we're at, average time, median time, max time, minimum time, average computation 
		  time and lastly the percent of the average time that the computational time takes up*/
		if(k % 2 == 0){
			printf("\\hline\\hline \n");
		}
		printf("%s & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f \\\\ \n", to_test[k], (total_time/test_number)/1000000.0, results[test_number/2]/1000000.0, max/1000000.0, min/1000000.0, (total_time_comp/test_number)/1000000.0, comp_percent, overall_ms/test_number, handshake_times_ms[test_number/2]);
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
