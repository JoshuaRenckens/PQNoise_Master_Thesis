#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include <disco_asymmetric.h>


// Size is max Noise message length + 2
static uint8_t message[65535 + 2];
static int test_number = 1000;
static char extra_front[4][5] = {"KN", "pqKN", "KX", "pqKX"};
static char send_key[8][5] = {"NK", "XK", "KK", "IK", "pqNK", "pqXK", "pqKK", "pqIK"};
static char rec_key[6][5] = {"KN", "KX", "KK", "pqKN", "pqKX", "pqKK"};
static char no_key[8][5] = {"NN", "XN", "KN", "IN", "pqNN", "pqXN", "pqKN", "pqIN"};
static char to_test[24][5] = {"NN", "pqNN", "NX", "pqNX", "NK", "pqNK", "XN", "pqXN", "XX", "pqXX", "XK", "pqXK",
				    "KN", "pqKN", "KX", "pqKX", "KK", "pqKK", "IN", "pqIN", "IX", "pqIX", "IK", "pqIK"};
static const char to_test_full_name[24][50] = {HANDSHAKE_NN, HANDSHAKE_PQ_NN,
				 	       HANDSHAKE_NX, HANDSHAKE_PQ_NX,
				 	       HANDSHAKE_NK, HANDSHAKE_PQ_NK,
				 	       HANDSHAKE_XN, HANDSHAKE_PQ_XN,
				 	       HANDSHAKE_XX, HANDSHAKE_PQ_XX,
				 	       HANDSHAKE_XK, HANDSHAKE_PQ_XK,
				 	       HANDSHAKE_KN, HANDSHAKE_PQ_KN,
				 	       HANDSHAKE_KX, HANDSHAKE_PQ_KX,
				 	       HANDSHAKE_KK, HANDSHAKE_PQ_KK,
				 	       HANDSHAKE_IN, HANDSHAKE_PQ_IN,
				 	       HANDSHAKE_IX, HANDSHAKE_PQ_IX,
				 	       HANDSHAKE_IK, HANDSHAKE_PQ_IK};

/*Access system counter for benchmarking*/
int64_t get_cpucycles()
{
  unsigned int hi, lo;

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

/* Check if the current pattern is in one of the above lists. Need to check whether we have to send a static key, or also have to send a byte to space the clients messages. The byte thing is necessary for the "KN" and "KX" pattern as the client would send his static key and afterwards the first actual handshake message and for some reason sending those two messages in a row messes up the second message. */
int in_list(int place, int index){
	char* elem = to_test[index];
	int res = 0;
	if(place == 0){
		for(int i = 0; i < 4; i++){
			res = max(!strcmp(extra_front[i], elem), res);
		}
	} else if (place == 1){
		for(int i = 0; i < 8; i++){
			res = max(!strcmp(send_key[i], elem), res);
		}
	} else if (place == 2){
		for(int i = 0; i < 6; i++){
			res = max(!strcmp(rec_key[i], elem), res);
		}
	} else if (place == 3){
		for(int i = 0; i < 8; i++){
			res = max(!strcmp(no_key[i], elem), res);
		}
	}
	return res;
}



int main(int argc, char const *argv[]) {
	
    	int key_size, socket_desc , new_socket , c;
    	struct sockaddr_in server , client;
    	size_t started;
    
        uint64_t total_time, total_time_comp, max, min, current;
    	uint64_t results[test_number];
    	uint64_t start2, stop2, start3, stop3;
    	
    	OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
  	pqkeyPair pq_server_static, pq_client_static;
  	keyPair server_static, client_static;
  	
  	// Not needed but necessary to not get errors
  	strobe_s s_write, s_read;
  	
   	/*Prepare socket and start listening*/
    
    	/*Create socket*/
    	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    	if (socket_desc == -1)
    	{
    		printf("Could not create socket");
    	}
    
    	/*Prepare the sockaddr_in structure*/
   	server.sin_family = AF_INET;
    	server.sin_addr.s_addr = INADDR_ANY;
    	server.sin_port = htons( 8888 );
    
    	/*Bind*/
    	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    	{
    		puts("bind failed");
    		return 1;
    	}
    	puts("Bind done");
    
    	/*Listen*/
    	listen(socket_desc , 3);
    	c = sizeof(struct sockaddr_in);
  	
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
		
		for(int i = 0; i <= test_number; i++){
		
			/*Create socket*/
			new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
			
			if (new_socket<0)
			{
			    puts("error");
			    return 1;
			}

			/*Preparation for the handshake*/
			
			/*Create own static key*/
			if (!in_list(3, k)){
				if(k%2 == 0){
					disco_generateKeyPair(&server_static);
				} else {
				    	generate_pqKeyPair(&pq_server_static, kem);
				}
			}
			
			/*Send client own static public key*/
			if(in_list(1, k)){
				int sent = -1;
				if(k%2 == 0){
					sent = send(new_socket, server_static.pub, key_size, 0);
				} else {
				    	sent = send(new_socket, pq_server_static.pub, key_size, 0);
				} 
				
				if (sent < 0) {
				    	puts("Error on receiving the public key");
				}
			}
			
			/*To avoid the client sending two messages back to back, needed for KX and KN handshakes*/
			if(in_list(0, k)){
				message[0] = 0;
				if (send(new_socket , message , 1 , 0) < 0) {
					puts("Error on 1 bit receive, client");
					break;
				}
			}
			
			/*Receive the clients public key, cause I'm not hardcoding an 800 byte key, and set the remote public key.*/	
			if (in_list(2, k)){
				int rec = -1;
				
				if(k%2 == 0){
					rec = recv(new_socket, client_static.pub, key_size, 0);
				} else {
				    	rec = recv(new_socket, pq_client_static.pub, key_size, 0);
				} 
				
				if (rec < 0) {
				    	puts("Error on receiving the public key");
				}
			}
			
			
			/*Initialize the handshake state with the protocol and the role*/
			handshakeState hs_server;
			
			if (!in_list(3, k)){
				if (in_list(2, k)){
					if(k%2 == 0){
						disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, &server_static, NULL, &client_static, NULL, 
							NULL, NULL, NULL, NULL, false);
					} else { 
					    	disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, NULL, NULL, 
							&pq_server_static, NULL, &pq_client_static, NULL, true);
					}
				} else {
					if(k%2 == 0){
						disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, &server_static, NULL, NULL, NULL, 
							NULL, NULL, NULL, NULL, false);
					} else { 
					    	disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, NULL, NULL, 
							&pq_server_static, NULL, NULL, NULL, true);
					}
				}
			} else {
				if (in_list(2, k)){
					if(k%2 == 0){
						disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, &client_static, NULL, 
							NULL, NULL, NULL, NULL, false);
					} else { 
					    	disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, NULL, NULL, 
							NULL, NULL, &pq_client_static, NULL, true);
					}
				} else {
					if(k%2 == 0){
						disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, NULL, NULL, 
							NULL, NULL, NULL, NULL, false);
					} else { 
					    	disco_Initialize(&hs_server, to_test_full_name[k], false, NULL, 0, NULL, NULL, NULL, NULL, 
							NULL, NULL, NULL, NULL, true);
					}
				}
			}
			
			/*Start the handshake*/
			started = 0;
			while(!hs_server.handshake_done){
				if(hs_server.sending){
					  size_t out_len;
					  
					  start3 = get_cpucycles();
					  bool ret = disco_WriteMessage(&hs_server, NULL, 0, message + 2, &out_len, &s_write, &s_read);
					  stop3 = get_cpucycles();
					  total_time_comp += stop3 - start3;
					  
					  if (!ret) {
						  printf("can't generate first handshake message\n");
						  return 1;
					  }

					  // add framing (2 bytes of length)
					  message[0] = (uint8_t) (out_len >> 8);
					  message[1] = (uint8_t) out_len;
					  out_len += 2;
					  
					  // send handshake message
					  ssize_t sent = send(new_socket, message, out_len, 0);
					  if (sent < 0) {
					    	printf("\nSending handshake message failed\n");
					    	return 1;
					  }
				} else {
					  // receive handshake message
					  ssize_t in_len = recv(new_socket, message, sizeof(message), 0);
					  if (in_len <= 0) {
						    printf("\nReceive second handshake message failed\n");
						    return 1;
					  }
					  
					  // Start measuring the servers time after it received the first message
					  if(!started){
					    	start2 = get_cpucycles();
					    	started = 1;
					  }

					  // parse handshake message
					  uint8_t payload[500];
          				  size_t payload_len;
					  start3 = get_cpucycles();
					  bool ret = disco_ReadMessage(&hs_server, message + 2, in_len-2, payload, &payload_len, &s_write, &s_read);
					  stop3 = get_cpucycles();
					  total_time_comp += stop3 - start3;
					  
					  if (!ret) {
						    printf("can't read handshake message\n");
						    abort();
					  }
				}
			}
			stop2 = get_cpucycles();
			current = stop2 - start2;
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
			}
			
			close(new_socket);
		}
		
		float comp_percent = ((float) total_time_comp) / ((float) total_time) * 100.0;
		qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
		/*Print in a format to copy paste into latex tables, in order of: what pattern we're at, average time, median time, max time, minimum time, average computation 
		  time and lastly the percent of the average time that the computational time takes up*/
		if(k % 2 == 0){
			printf("\\hline\\hline \n");
		}
		printf("%s & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f \\\\ \n", to_test[k], (total_time/test_number)/1000000.0, results[test_number/2]/1000000.0, max/1000000.0, min/1000000.0, (total_time_comp/test_number)/1000000.0, comp_percent);
		if(k % 2 == 0){
			printf("\\hline \n");
		}
	}
	    
	close(socket_desc);
	return 0;
}
