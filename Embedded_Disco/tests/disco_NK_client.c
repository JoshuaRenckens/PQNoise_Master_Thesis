#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <disco_asymmetric.h>

static uint8_t const pub_static_key[32] = {
    0x4d, 0xfe, 0xb6, 0xba, 0x4a, 0x7b, 0xcd, 0xf0,
    0x58, 0x1d, 0x9c, 0x31, 0x53, 0x64, 0xb5, 0x03,
    0xd9, 0xe1, 0x42, 0x41, 0xb1, 0xae, 0xf4, 0x04,
    0x56, 0x0d, 0x32, 0xc0, 0xb6, 0xe3, 0xd9, 0x56
};

int main(int argc, char const *argv[]) {
  // set the known public static key of the server
  keyPair server_keypair;
  for(int i = 0; i < 32; i++){
    server_keypair.pub[i] = pub_static_key[i];
  }
  
  // initialize socket
  struct sockaddr_in server;
  int socket_desc = 0;
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("127.0.0.1");
  server.sin_port = htons( 8888 );

  // initialize disco for the client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_NK, true, NULL, 0, NULL, NULL,
                   &server_keypair, NULL, NULL, NULL, NULL, NULL, false);
                 

  // connect
  if ((socket_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return 1;
  }
  
  if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    printf("\nConnection Failed \n");
    return 1;
  }


  // generate the first handshake message
  uint8_t out[500];
  size_t out_len;
  bool ret =
      disco_WriteMessage(&hs_client, NULL, 0, out + 2, &out_len, NULL, NULL);
  if (!ret) {
    printf("can't generate first handshake message\n");
    return 1;
  }

  // add framing (2 bytes of length)
  out[0] = (out_len >> 8) & 0xFF;
  out[1] = out_len & 0xFF;
  out_len += 2;
  
  // send first handshake message
  ssize_t sent = send(socket_desc, out, out_len, 0);
  if (sent < 0) {
    printf("\nSending first handshake message failed\n");
    return 1;
  }

  // receive second handshake message
  uint8_t in[500];
  ssize_t in_len = recv(socket_desc, in, 500, 0);
  if (in_len <= 0) {
    printf("\nReceive second handshake message failed\n");
    return 1;
  }

  printf("received %zd bytes\n", in_len);

  // remove framing
  size_t length = (in[0] << 8) | in[1];
  printf("without framing: %zu bytes\n", length);
  if (length != in_len - 2) {
    printf("\nmessage was possibly fragmented, we don't handle that\n");
    return 1;
  }
  in_len = length;

  // parse second handshake message
  strobe_s c_write;
  strobe_s c_read;
  uint8_t payload[500];
  size_t payload_len;
  if (in_len > 500) {
    printf("\nwe don't support this yet\n");
    return 1;
  }
  printf("in_len: %ld\n", in_len);
  ret = disco_ReadMessage(&hs_client, in + 2, in_len, payload, &payload_len,
                          &c_write, &c_read);
  if (!ret) {
    printf("can't read handshake message\n");
    abort();
  }
  
  // print out payload/payload_len
  assert(strobe_isInitialized(&c_read) && strobe_isInitialized(&c_write));

  printf("handshake done!\n");
  close(socket_desc);
}
