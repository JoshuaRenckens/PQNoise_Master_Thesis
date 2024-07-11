#include <stdio.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

const char* host = "10.0.0.1:4433";

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

int comp2(const void* elem1, const void* elem2){
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
    uint64_t total_time = 0, max = 0, min = INT_MAX, current = 0;
    uint64_t results[test_number];
    double results_ms[test_number];
    uint64_t start, stop;
    
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
    
    ret = SSL_CTX_set1_groups_list(ssl_ctx, "kyber512");
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, "CA.crt", 0);
    if(ret != 1)
    {
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    for(int i = 0; i <= test_number; i++){
	    clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	    start = get_cpucycles();
	    ssl = do_tls_handshake(ssl_ctx);
	    stop = get_cpucycles();
	    clock_gettime(CLOCK_MONOTONIC_RAW, &finish);

	    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
	    ret = BIO_closesocket(SSL_get_fd(ssl));
	    if(ret == -1)
	    {
		goto ossl_error;
	    }

	    SSL_free(ssl);
	    
	    current = stop - start;
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
		results_ms[i-1] = ((finish.tv_sec - begin.tv_sec) * MS_IN_S) + ((finish.tv_nsec - begin.tv_nsec) / NS_IN_MS);
	    }
	    
    }
    
    qsort(results, sizeof(results)/sizeof(*results), sizeof(*results), comp);
    qsort(results_ms, sizeof(results_ms)/sizeof(*results_ms), sizeof(*results_ms), comp2);
    printf("Kyber512 & %7.2f & %7.2f & %7.2f & %7.2f & %7.2f\\\\ \n", (total_time/test_number)/1000000.0, results[500]/1000000.0, max/1000000.0, min/1000000.0, results_ms[500]);
    
    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
