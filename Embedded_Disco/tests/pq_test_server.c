#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <disco_asymmetric.h>

int main(int argc, char const *argv[]) {
  int socket_desc , new_socket , c;
  struct sockaddr_in server , client;
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
  pqkeyPair server_static;
  kem->keypair(server_static.pub, server_static.priv);
  //pqkeyPair client_static;
  

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
  while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
  {
  
	  send(new_socket, server_static.pub, 800, 0);
	  //recv(new_socket, client_static.pub, 800, 0);
  	  // initialize disco with the PQ_NK pattern
	  handshakeState hs_server;
	  disco_Initialize(&hs_server, HANDSHAKE_PQ_NK, false, NULL, 0, NULL,
		           NULL, NULL, NULL, &server_static, NULL, NULL, NULL, true);
		           
	  // receive first handshake message
	  uint8_t in[2000];
	  ssize_t in_len = recv(new_socket, in, 2000, 0);
	  if (in_len <= 0) {
	    printf("\nReceive first handshake message failed\n");
	    printf("Error: %s, number %d", strerror(errno), errno);
	    return 1;
	  }
		      
	  // remove framing
	  size_t length = (in[0] << 8) | in[1];
	  printf("without framing: %zu bytes\n", length);
	  if (length != in_len - 2) {
	    printf("\nmessage was possibly fragmented, we don't handle that\n");
	    return 1;
	  }
	  in_len = length;

	  // process the first handshake message
	  uint8_t payload[2000];
          size_t payload_len;
	  bool ret = disco_ReadMessage(&hs_server, in + 2, in_len, payload, &payload_len, NULL, NULL);
	  if (!ret) {
	    abort();
	  }

	  // create second handshake message
	  uint8_t out[2000];
	  size_t out_len;
	  strobe_s s_write;
  	  strobe_s s_read;
	  ret = disco_WriteMessage(&hs_server, NULL, 0,
		                               out + 2, &out_len, &s_write, &s_read);
	  if (!ret) {
	    abort();
	  }

	  // add framing (2 bytes of length)
	  out[0] = (out_len >> 8) & 0xFF;
	  out[1] = out_len & 0xFF;
	  out_len += 2;

	  // send second handshake message
	  puts("We got here");
	  size_t sent = send(new_socket, out, out_len, 0);
	  if (sent < 0) {
	    printf("\nSending second handshake message failed\n");
	    return 1;
	  }
	  break;
  }
  
  if (new_socket<0)
  {
  	perror("accept failed");
    	return 1;
  }
    
  puts("Handshake finished \n");
  close(socket_desc);
  close(new_socket);
}
