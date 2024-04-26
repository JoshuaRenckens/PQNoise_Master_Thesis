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

static uint8_t const priv_static_key[32] = {
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
};

int main(int argc, char const *argv[]) {
  int socket_desc , new_socket , c;
  struct sockaddr_in server , client;
  // set the longterm static key for the server
  keyPair server_keypair;
  for(int i = 0; i < 32; i++){
    server_keypair.priv[i] = priv_static_key[i];
    server_keypair.pub[i] = pub_static_key[i];
  }
  
  // initialize disco with the NK pattern
  handshakeState hs_server;
  disco_Initialize(&hs_server, HANDSHAKE_NK, false, NULL, 0, &server_keypair,
                   NULL, NULL, NULL, NULL, NULL, NULL, NULL false);

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
	  // receive first handshake message
	  uint8_t in[500];
	  ssize_t in_len = recv(new_socket, in, 500, 0);
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
	  uint8_t payload[500];
          size_t payload_len;
	  bool ret = disco_ReadMessage(&hs_server, in + 2, in_len, payload, &payload_len, NULL, NULL);
	  if (!ret) {
	    abort();
	  }

	  // create second handshake message
	  uint8_t out[500];
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
