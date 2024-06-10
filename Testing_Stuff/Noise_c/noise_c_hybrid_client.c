#include <limits.h>
#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

static uint8_t message[65535 + 2];
static int test_number = 1000;
static char extra_receive_front[3][6] = {"KNhyb", "KXhyb", "KKhyb"};
static char extra_receive_mid[2][6] = {"KNhyb", "KXhyb"};
static char extra_send_front[4][6] = {"NKhyb", "XKhyb", "IKhyb", "KKhyb"};
static char extra_send_back[3][6] = {"NKhyb","IKhyb", "XKhyb"};
static char extra_receive_back[3][6] = {"NXhyb", "KXhyb", "IXhyb"};
static char send_key[3][6] = {"KNhyb", "KXhyb", "KKhyb"};
static char to_test[12][6] = {"NNhyb", "NXhyb", "NKhyb", "XNhyb", "XXhyb", "XKhyb", "KNhyb", "KXhyb", "KKhyb", "INhyb", "IXhyb", "IKhyb"};
static const char to_test_full_name[12][50] = {"Noise_NNhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_NXhyb_25519+Kyber512_ChaChaPoly_BLAKE2s", 
				 	       "Noise_NKhyb_25519+Kyber512_ChaChaPoly_BLAKE2s", 
				 	       "Noise_XNhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_XXhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_XKhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_KNhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_KXhyb_25519+Kyber512_ChaChaPoly_BLAKE2s", 
				 	       "Noise_KKhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_INhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_IXhyb_25519+Kyber512_ChaChaPoly_BLAKE2s",
				 	       "Noise_IKhyb_25519+Kyber512_ChaChaPoly_BLAKE2s"};

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

int max(int a, int b){
	if(a > b){
		return a;
	} else {
		return b;
	}
}

// Check if the current pattern is in one of the above lists. Needed to know when we need to send an extra bit before start/after finish of the handshake to keep messages apart, also needed to know if 
// we need to send the static key beforehand for the k patterns.
int in_list(int place, int index){
	char* elem = to_test[index];
	int res = 0;
	if(place == 0){
		for(int i = 0; i < 3; i++){
			res = max(!strcmp(extra_receive_front[i], elem), res);
		}
	} else if (place == 1){
		for(int i = 0; i < 3; i++){
			//printf("What we have: %s, what we check for: %s, index: %d\n", elem, extra_send_back[i], i);
			res = max(!strcmp(extra_send_back[i], elem), res);
		}
	} else if (place == 2){
		for(int i = 0; i < 3; i++){
			res = max(!strcmp(extra_receive_back[i], elem), res);
		}
	} else if (place == 3){
		for(int i = 0; i < 3; i++){
			res = max(!strcmp(send_key[i], elem), res);
		}
	} else if (place == 4){
		for(int i = 0; i < 4; i++){
			res = max(!strcmp(extra_send_front[i], elem), res);
		}
	}
	else if (place == 5){
		for(int i = 0; i < 2; i++){
			res = max(!strcmp(extra_receive_mid[i], elem), res);
		}
	}
	return res;
}


int main(int argc, char *argv[])
{
	NoiseDHState *dh;
	NoiseHandshakeState *handshake;
	int err, action, key_size, socket_desc, hyb_key_size;
	struct sockaddr_in server;
	NoiseBuffer mbuf;
	size_t message_size, received, full_size;
	
	uint64_t total_time, total_time_comp,max, min, current;
	uint64_t results[1000];
	uint64_t start2, stop2, start3, stop3;


	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("10.0.0.1");
	server.sin_port = htons( 8888 );

	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("connect error");
		return 1;
	}

	puts("Connected\n");
	
	// Go through the list of handshake names and run them all.
    	for(int k = 0; k < 12; k++){
	    	// Set the correct key size, the regular handshakes are at even positions in the list while the pq ones are not.
		key_size = 32;
		hyb_key_size = 800;
	    	
	    	total_time = 0;
		total_time_comp = 0;
		max = 0;
		min = INT_MAX;
		current = 0;
	    
	    	//printf("\nStarting runs for %s handshake.\n", to_test[k]);
	    	// Run the handshake test_number of times
	    	
		for(int i = 0; i <= test_number; i++){
		
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
			if(in_list(3, k)){
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
			
			// To avoid the client sending two messages back to back, needed for KX and KN handshakes
			if(in_list(0, k)){
				message_size = recv(socket_desc, message , sizeof(message) , 0);
				if(message_size != 1){
					puts("Error on 1 bit receive, client");
				    	break;
				}
			}
			
			/*Create own hybrid static key*/
			if (noise_handshakestate_needs_local_hybrid_keypair(handshake)){
				dh = noise_handshakestate_get_local_hybrid_keypair_dh(handshake);
				//start2 = get_cpucycles();
				err = noise_dhstate_generate_keypair(dh);
				//stop2 = get_cpucycles();
				//printf("Time taken to create static key: %ld cycles.\n", stop2 - start2);
				if (err != NOISE_ERROR_NONE) {
				    noise_perror("Generate key", err);
				    return 1;
				}
			}
			
			/*Send server own hybrid public key*/
			if(in_list(3, k)){
				err = noise_dhstate_get_public_key(dh, message, hyb_key_size);
				if (err != NOISE_ERROR_NONE) {
				    noise_perror("Get public key", err);
				    return 1;
				}
				int sent = send(socket_desc, message, hyb_key_size, 0);
				if (sent < 0) {
				    	puts("Error on receiving the public key");
				}
			}
			
			// To avoid the client sending two messages back to back, needed for KX and KN handshakes
			if(in_list(5, k)){
				message_size = recv(socket_desc, message , sizeof(message) , 0);
				if(message_size != 1){
					puts("Error on 1 bit receive, client");
				    	break;
				}
			}
			
			
			/*Receive the servers static public key, and set the remote public key.*/	
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
			
			
			// To avoid the server sending two messages in a row
			if(in_list(4, k)){
				message[0] = 0;
				if (send(socket_desc , message , 1 , 0) < 0) {
					puts("Error on 1 bit receive, client");
					break;
				}
			}
			
			/*Receive the servers static hybrid public key, and set the remote public key.*/
			if (noise_handshakestate_needs_remote_hybrid_public_key(handshake)){
				int rec = recv(socket_desc, message, hyb_key_size, 0);
				if (rec < 0) {
				    	puts("Error on receiving the public key");
				}
				dh = noise_handshakestate_get_remote_hybrid_public_key_dh(handshake);
				err = noise_dhstate_set_public_key(dh, message, hyb_key_size);
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
				    total_time_comp += stop3 - start3;
				    
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
				    total_time_comp += stop3 - start3;
				    
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
			//printf("\nTime taken by run %d: %ld cycles.\n", i, current);
			//printf("Current total time: %ld cycles.\n", total_time);
			
			if(ok == 0){
				puts("Handshake failed\n");
			}
			
			if (in_list(1, k)) {
				message[0] = 0;
				if (send(socket_desc , message , 1 , 0) < 0) {
					puts("Error on final send, server");
					ok = 0;
					break;
				}
				//puts("Final send done, server\n\n");
			} else if (in_list(2, k)){
				message_size = recv(socket_desc, message , sizeof(message) , 0);
				if(message_size != 1){
					puts("Error on final receive, client");
					ok = 0;
				    	break;
				}
				//puts("Final receive done, client\n\n");
			}
			
		}
		float comp_percent = ((float) total_time_comp) / ((float) total_time) * 100;
		qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
		if(k % 2 == 0){
			printf("\\hline \n");
		}
		printf("%s & %5.1f & %5.1f & %5.1f & %5.1f & %5.2f & %5.2f \\\\ \n", to_test[k], (total_time/test_number)/1000000.0, results[500]/1000000.0, max/1000000.0, min/1000000.0, (total_time_comp/test_number)/1000000.0, comp_percent);
		if(k % 2 == 0){
			printf("\\hline \n");
		}
		/*printf("Average time taken by the handshakes: %ld cycles.\n", total_time/test_number);
		printf("Average time taken for the computations: %ld cycles.\n", total_time_comp/test_number);
        	printf("On average %5.2f percent of the total time is computation.\n\n", comp_percent);
		printf("Median time taken by the handshakes: %ld cycles.\n", results[500]);
		printf("Maximum time taken by the handshakes: %ld cycles.\n", max);
		printf("Minimum time taken by the handshakes: %ld cycles.\n", min);*/
	}
	close(socket_desc);

	return 0;
}
