#include "internal.h"
#include <string.h>

#include <oqs/oqs.h>
#include <time.h>

uint64_t start, stop;

int64_t cpucycles()
{ // Access system counter for benchmarking
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
}

/*
 * Kyber stuff, should be put in a seperate file but I don't know how to change the makefile here
 * Currently missing the SEEC scheme when generating, only to be used in conjunction with the PQNoise patterns
*/

// Create OQS_KEM object initialized with kyber 512.

typedef struct
{
    struct NoiseDHState_s parent;
    OQS_KEM* kem;
    uint8_t private_key[1632];
    uint8_t public_key[800];

} NoiseKyberState;

static int noise_kyber_generate_keypair
        (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    start = cpucycles();
    st->kem->keypair(st->public_key, st->private_key);
    stop = cpucycles();
    return NOISE_ERROR_NONE;
}

/*No function given to generate a kyber public key from the private key and I don't feel like writing one at the moment*/
static int noise_kyber_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    /* Doing nothing for now*/
    return NOISE_ERROR_NONE;
}

static int noise_kyber_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    memcpy(st->public_key, public_key, 800);
    memcpy(st->private_key, private_key, 1632);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here */
    return NOISE_ERROR_NONE;
}

static int noise_kyber_copy
        (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    const NoiseKyberState *from_st = (const NoiseKyberState *)from;
    memcpy(st->private_key, from_st->private_key, 1632);
    memcpy(st->public_key, from_st->public_key, 800);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_calculate
        (const NoiseDHState *private_key_state,
         const NoiseDHState *public_key_state,
         uint8_t *shared_key)
{
    /*Nothing to do here*/
    return NOISE_ERROR_NONE;
}

static int noise_kyber_encapsulate
        (const NoiseDHState *state, uint8_t *cipher, uint8_t *shared)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    start = cpucycles();
    st->kem->encaps(cipher, shared, st->public_key);
    stop = cpucycles();
    return NOISE_ERROR_NONE;
}

static int noise_kyber_decapsulate
        (const NoiseDHState *state, const uint8_t *cipher, uint8_t *shared)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    st->kem->decaps(shared, cipher, st->private_key);
    return NOISE_ERROR_NONE;
}

NoiseDHState *pqnoise_kyber_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;
    state->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    state->parent.dh_id = NOISE_DH_KYBER;
    state->parent.pq_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = 1632;
    state->parent.public_key_len = 800;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_kyber_generate_keypair;
    state->parent.set_keypair = noise_kyber_set_keypair;
    state->parent.set_keypair_private = noise_kyber_set_keypair_private;
    state->parent.validate_public_key = noise_kyber_validate_public_key;
    state->parent.copy = noise_kyber_copy;
    state->parent.calculate = noise_kyber_calculate;
    state->parent.encaps = noise_kyber_encapsulate;
    state->parent.decaps = noise_kyber_decapsulate;
    return &(state->parent);
}
