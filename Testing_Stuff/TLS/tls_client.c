#include <stdio.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

const char* host = "10.0.0.1:4433";

/*Access system counter for benchmarking*/
/*int64_t get_cpucycles()
{ 
#if defined(__GNUC__) && defined(__ARM_ARCH_7A__)
	// Case for the board
        uint32_t r = 0;
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(r) );
        return r;
#else
	// Case for a laptop with an intel cpu
	unsigned int hi, lo;
  
  	asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  	return ((int64_t)lo) | (((int64_t)hi) << 32);
#endif
}*/

int comp(const void* elem1, const void* elem2){
	double val1 = *((double*)elem1);
	double val2 = *((double*)elem2);
	return (val1 > val2) - (val1 < val2);
}

static int test_number = 1000;

SSL* do_tls_handshake(SSL_CTX* ssl_ctx)
{
    BIO* conn;
    SSL* ssl;
    int ret;

    conn = BIO_new(BIO_s_connect());
    if (!conn)
    {
        return 0;
    }

    BIO_set_conn_hostname(conn, host);
    BIO_set_conn_mode(conn, BIO_SOCK_NODELAY);

    ssl = SSL_new(ssl_ctx);

    SSL_set_bio(ssl, conn, conn);

    // ok, lets connect
    ret = SSL_connect(ssl);
    if (ret <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return 0;
    }
    
    return ssl;
}

int main(int argc, char* argv[])
{

    if(argc != 3){
	puts("Wrong amount of arguments, expected 2.");
	return 1;
    }
    
    double results_ms[test_number], total_time = 0;
    
    int ret = -1;
    SSL_CTX* ssl_ctx = 0;

    const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const SSL_METHOD* ssl_meth = TLS_client_method();
    SSL* ssl = NULL;

    struct timespec begin, finish;

    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        goto ossl_error;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites);
    if (ret != 1)
    {
        goto ossl_error;
    }
    
    ret = SSL_CTX_set1_groups_list(ssl_ctx, argv[1]);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, "./Keys/CA.crt", 0);
    if(ret != 1)
    {
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    for(int i = 0; i <= test_number; i++){
	    clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	    
	    ssl = do_tls_handshake(ssl_ctx);
	    
	    clock_gettime(CLOCK_MONOTONIC_RAW, &finish);

	    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
	    ret = BIO_closesocket(SSL_get_fd(ssl));
	    if(ret == -1)
	    {
		goto ossl_error;
	    }

	    SSL_free(ssl);
	    
	    // One run to warm the cache where we won't include the time
	    if(i != 0){
	    	results_ms[i-1] = ((finish.tv_sec - begin.tv_sec) * MS_IN_S) + ((finish.tv_nsec - begin.tv_nsec) / NS_IN_MS);
		total_time += results_ms[i-1];
	    }
	    
    }
    
    qsort(results_ms, sizeof(results_ms)/sizeof(*results_ms), sizeof(*results_ms), comp);
    printf("\\hline\\hline \n");
    printf("%s&%s&%.2f&%.2f&%.2f&%.2f&%.2f&%.2f\\\\\n",argv[2], argv[1], total_time/test_number, results_ms[test_number/2], results_ms[75*(test_number/100)], results_ms[95*(test_number/100)], results_ms[test_number-1], results_ms[0]);
    
    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
