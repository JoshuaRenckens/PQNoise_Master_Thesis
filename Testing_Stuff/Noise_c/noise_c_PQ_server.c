#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/*static uint8_t const priv_static_key[32] = {
    0x20, 0x1f, 0xb3, 0x99, 0xcf, 0x1e, 0x85, 0xbc,
    0xf3, 0xe0, 0x33, 0xf5, 0x0b, 0x29, 0x06, 0x2e,
    0x81, 0x81, 0x52, 0xe7, 0xb1, 0xc5, 0x83, 0xbe,
    0x20, 0x9c, 0x46, 0x5a, 0x5e, 0x2d, 0x57, 0x5a
};

static uint8_t const pub_static_key[32] = {
    0x4d, 0xfe, 0xb6, 0xba, 0x4a, 0x7b, 0xcd, 0xf0,
    0x58, 0x1d, 0x9c, 0x31, 0x53, 0x64, 0xb5, 0x03,
    0xd9, 0xe1, 0x42, 0x41, 0xb1, 0xae, 0xf4, 0x04,
    0x56, 0x0d, 0x32, 0xc0, 0xb6, 0xe3, 0xd9, 0x56
};*/

// Size is max message length + 2
static uint8_t message[65535 + 2];
static int test_number = 1000;
static uint64_t start2, stop2, start3, stop3;
static char extra_front[4][5] = {"KN", "pqKN", "KX", "pqKX"};
static char extra_receive_back[5][5] = {"NK", "pqNK","IK", "pqIK", "pqXK"};
static char extra_send_back[5][5] = {"XN", "XX", "pqNX", "pqKX", "pqIX"};
static char send_key[8][5] = {"NK", "XK", "KK", "IK", "pqNK", "pqXK", "pqKK", "pqIK"};
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
		for(int i = 0; i < 4; i++){
			res = max(!strcmp(extra_front[i], elem), res);
		}
	} else if (place == 1){
		for(int i = 0; i < 5; i++){
			//printf("What we have: %s, what we check for: %s\n", elem, extra_send_back[i]);
			res = max(!strcmp(extra_send_back[i], elem), res);
		}
	} else if (place == 2){
		for(int i = 0; i < 5; i++){
			res = max(!strcmp(extra_receive_back[i], elem), res);
		}
	} else {
		for(int i = 0; i < 8; i++){
			res = max(!strcmp(send_key[i], elem), res);
		}
	}
	return res;
}


int main(int argc, char *argv[])
{
    NoiseDHState *dh;
    NoiseHandshakeState *handshake;
    int err, action, key_size, socket_desc , new_socket , c, started;
    struct sockaddr_in server , client;
    NoiseBuffer mbuf;
    size_t message_size, received, full_size;
    
    uint64_t total_time, total_time_comp, max, min, current;
    uint64_t results[test_number];
    
    
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
    	printf("Could not create socket");
    }
    
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );
    
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
    	puts("bind failed");
    	return 1;
    }
    puts("Bind done");
    
    //Listen
    listen(socket_desc , 3);
    
    //Accept incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    
    if (new_socket<0)
    {
    	perror("accept failed");
    	return 1;
    
    }
    
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
        min = 10000000000;
        current = 0;
    
    	printf("\nStarting runs for %s handshake.\n", to_test[k]);
    	// Run the handshake test_number of times
    	for(int i = 0; i <= test_number; i++){
    
	    	/*Initialize the handshake state with the protocol and the role*/
		err = noise_handshakestate_new_by_name(&handshake,  to_test_full_name[k], NOISE_ROLE_RESPONDER);
	 	if (err != NOISE_ERROR_NONE) {
			noise_perror(to_test_full_name[k], err);
			return 1;
		}
		
		/*Receive the clients static public key*/
		if (noise_handshakestate_needs_remote_public_key(handshake)){
			int rec = recv(new_socket, message, key_size, 0);
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
		
		// To avoid the client sending two messages back to back
		if(in_list(0, k)){
			message[0] = 0;
			if (send(new_socket , message , 1 , 0) < 0) {
				puts("Error on 1 bit receive, client");
				break;
			}
		}
			
		/*Generate a new static keypair for the server*/
		if (noise_handshakestate_needs_local_keypair(handshake)){
			dh = noise_handshakestate_get_local_keypair_dh(handshake);
			err = noise_dhstate_generate_keypair(dh);
			if (err != NOISE_ERROR_NONE) {
			    noise_perror("Generate key", err);
			    return 1;
			}
		}
		
		/*Send the generated static public key to the client, cause I don't want to hardcode an 800 byte key*/
		if(in_list(3, k)){
			err = noise_dhstate_get_public_key(dh, message, key_size);
			if (err != NOISE_ERROR_NONE) {
			    noise_perror("Get public key", err);
			    return 1;
			}
			int sent = send(new_socket, message, key_size, 0);
			if (sent < 0) {
			    	puts("Error on receiving the public key");
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
	    	started = 0;
		while (ok) {
		
			action = noise_handshakestate_get_action(handshake);
			if (action == NOISE_ACTION_WRITE_MESSAGE) {
			    /* Write the next handshake message with a zero-length payload */
			    noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
			    
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
				    	puts("Error on receive, server");
					ok = 0;
					break;
				    }
				    if(full_size == 1){
				    	full_size = (message[0] << 8) + message[1];
				    }
				    received += message_size;
				    //printf("Message_size: %ld, Full size: %ld, Received: %ld\n", message_size, full_size, received);
			    }
			    // Start measuring the servers time after it received the first message
			    if(!started){
			    	start2 = get_cpucycles();
			    	started = 1;
			    }
			    noise_buffer_set_input(mbuf, message + 2, received - 2);
			    
			    start3 = get_cpucycles();
			    
			    err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
			    
			    stop3 = get_cpucycles();
			    //printf("Read, buffer size: %ld\n", mbuf.size);
			    //printf("Received: %ld\n", received);
			    //printf("Time taken to process the message: %ld cycles.\n", stop3 - start3);
			    total_time_comp += stop3 - start3;
			    
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
			if (send(new_socket , message , 1 , 0) < 0) {
				puts("Error on final send, server");
				ok = 0;
				break;
			}
			//puts("Final send done, server\n\n");
		} else if (in_list(2, k)){
			message_size = recv(new_socket, message , sizeof(message) , 0);
			if(message_size != 1){
				puts("Error on final receive, server");
				ok = 0;
			    	break;
			}
			//puts("Final receive done, client\n\n");
		}
	}
	
	float comp_percent = ((float) total_time_comp) / ((float) total_time) * 100;
        qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
        printf("Average time taken by the handshakes: %ld cycles.\n", total_time/test_number);
        printf("Average time taken for the computations: %ld cycles.\n", total_time_comp/test_number);
        printf("On average %5.2f percent of the total time is computation.\n\n", comp_percent);
        printf("Median time taken by the handshakes: %ld cycles.\n", results[500]);
        printf("Maximum time taken by the handshakes: %ld cycles.\n", max);
        printf("Minimum time taken by the handshakes: %ld cycles.\n\n\n", min);
    }

    
    
    close(new_socket);
    close(socket_desc);
    
    return 0;
}
