#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <disco_asymmetric.h>

int main(int argc, char const *argv[]) {
  
  // initialize socket
  struct sockaddr_in server;
  int socket_desc = 0;
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("127.0.0.1");
  server.sin_port = htons( 8888 );
  pqkeyPair server_static;
  //OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
  //pqkeyPair client_static;
  //kem->keypair(client_static.pub, client_static.priv);
                 

  // connect
  if ((socket_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return 1;
  }
  
  if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    printf("\nConnection Failed \n");
    return 1;
  }

  recv(socket_desc, server_static.pub, 800, 0);
  //send(socket_desc, client_static.pub, 800, 0);
  // initialize disco for the client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_PQ_NK, true, NULL, 0, NULL, NULL,
                   NULL, NULL, NULL, NULL, &server_static, NULL, true);
                   

  // generate the first handshake message
  uint8_t out[2000];
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
  uint8_t in[2000];
  ssize_t in_len = recv(socket_desc, in, 2000, 0);
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
  uint8_t payload[2000];
  size_t payload_len;
  if (in_len > 2000) {
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
