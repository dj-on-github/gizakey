// SP800-90A AES-256 CTR DRBG 
// dj.johnston@intel.com

// Version 0.[it is not nearly done yet]
// TBD:
//      Add a flags style command interface to better match the spec
//      Harden it from fault injection
//      Check against NIST Vectors
//      Add a get_noise() function using RdSeed or RdRand
//      Add AES-NI support
//      Add input checking (for zero pointers etc.)

#define CTR_AES256_DRBG_ERR_SUCESS 1
#define CTR_AES256_DRBG_ERR_RESEED_REQUIRED -1

typedef  struct {
    unsigned int c;
    unsigned char key256[32];
    unsigned char vector128[16];
    unsigned int security_strength;
    unsigned int prediction_resistance;
    unsigned int reseed_interval;
    unsigned int rdrand;
    unsigned int rdseed;
} t_sp800_90a_ctr_aes256_drbg_state;

// Low Level Access Routines
int ctr_aes_256_drbg_update(unsigned char *provided_data, unsigned int provided_data_length, t_sp800_90a_ctr_aes256_drbg_state* state);
int ctr_aes_256_drbg_instantiate(
            unsigned char *entropy_input,unsigned int entropy_input_length,
            unsigned char *personalization_string, unsigned int personalization_string_length,
            t_sp800_90a_ctr_aes256_drbg_state* state);
int ctr_aes_256_drbg_uninstantiate(t_sp800_90a_ctr_aes256_drbg_state* state);
int ctr_aes_256_drbg_reseed(
            unsigned char *entropy_input,unsigned int entropy_input_length,
            unsigned char *additional_input,unsigned int additional_input_length,
            t_sp800_90a_ctr_aes256_drbg_state* state);
int ctr_aes_256_drbg_generate(
            unsigned int requested_blocks, 
            //unsigned int prediction_resistance_req,
            //unsigned char *entropy_input,unsigned int entropy_input_length,
            //unsigned char *additional_input,unsigned int additional_input_length,
            unsigned char *output,
            t_sp800_90a_ctr_aes256_drbg_state* state);

// Initialize entropy source - In this case 
unsigned int rng_svc_initialize_entropy_source(t_sp800_90a_ctr_aes256_drbg_state *rng_instance);
            
// Noise source and conditioner access
//   Returns num_of_bytes bytes of raw data into the location pointed to by buffer
int rng_get_noise(unsigned char *buffer, unsigned int num_of_bytes, t_sp800_90a_ctr_aes256_drbg_state *state);

// High level command interface

// Buffer type for passing byte strings of data to and from the high level command interface.
typedef struct {
    unsigned int length;
    unsigned char *buffer;
} t_buffer;

// The Command Interface
//    Commands IDs are randomized into a large number space for fault injection tolerance.
//
//    RNG_CMD_INSTANTIATE. Instantiate the DRBG
//      Inputs:
//          personalization_string
//      Flags:
//          None
//      Outputs:
//          rng_instance
//
//    RNG_CMD_UNINSTANTIATE. Uninstantiate the DRBG
//      Inputs:
//          None
//      Flags:
//          None
//      Outputs:
//          None
//
//    RNG_CMD_GENERATE. Generate data from the DRBG
//      Inputs:
//          additional_data
//          output buffer location & length
//      Flags:
//          PREDICTION_RESISTANCE_REQ
//          or
//          PREDICTION_RESISTANCE_OFF
//      Outputs:
//          status=SUCCESS && output buffer
//          or
//          status=ERROR
//
//    RNG_CMD_RESEED. Reseed the DRBG
//      Inputs:
//          additional_input
//      Flags:
//          None
//      Outputs:
//          status=SUCCESS
//          or
//          status=ERROR
//
//    RNG_CMD_GETNOISE. Instantiate the DRNG
//      Inputs:
//          output buffer location and length
//      Flags:
//          None
//      Outputs:
//          status=SUCCESS && output buffer
//          or
//          status=ERROR

// Command Encodings
//   Encodings are randomly chosed for fault injection hardening
#define RNG_CMD_INSTANTIATE    0x8c0980ab
#define RNG_CMD_UNINSTANTIATE  0xce256b12
#define RNG_CMD_GENERATE       0x817362ef
#define RNG_CMD_RESEED         0x3df0233c
#define RNG_CMD_GETNOISE       0x8e7f7d8b

// Flag Encodings
//   Flags each use 3 bits, spread randomly, for fault injection hardening
//   NO_FLAGS encoding is a randomly chosen value.
//   Every flag has a REQ and and OFF value independent.
//   The absence of a flag when it's required is an error
//   If there are no flags at all, NO_FLAGS must be used. Not 0x00000000.
#define PREDICTION_RESISTANCE_REQ  0x01208000
#define PREDICTION_RESISTANCE_OFF  0x00000301
#define NO_FLAGS                   0x0e1701a6
// Remaining unused flags are:
// 0x80020008
// 0x00880800
// 0x00040006
// 0x02003000
// 0x400000A0
// 0x40100010

// Status Encodings
//   Encodings are randomly chosen for fault injection hardening
#define RNG_STATUS_SUCCESS                           0xdfa4b09d
#define RNG_STATUS_ERROR_INVALID_PARAMETERS          0x6f85bd21
#define RNG_STATUS_ERROR_NOISE_UNAVAILABLE           0x31e4b390
#define RNG_STATUS_ERROR_RESEED_REQUIRED             0x79f34fad
#define RNG_STATUS_ERROR_UNKNOWN_COMMAND             0x26c5060f
#define RNG_STATUS_ERROR_NOT_INTEL                   0x7389fa45
#define RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE 0x99e62ff0


// RNG Command Function
//int rng_command(unsigned int command, unsigned int flags, t_buffer *additional_input, t_buffer *personalization_string,t_buffer *destination, t_sp800_90a_ctr_aes256_drbg_state *rng_instance);

int rng_command(unsigned int command, unsigned int flags, t_buffer *additional_input, t_buffer *personalization_string,t_buffer *destination, t_sp800_90a_ctr_aes256_drbg_state *rng_instance);

// Example:
// #include <stdio.h>
// #include "sp800_90_ctr_aes256_drbg.h"
//
// #define RANDOM_BUFFSIZE = 1024
// t_buffer personalization_string_a = { .length=10, .buffer="needlework" };
// t_buffer personalization_string_b = { .length=7,  .buffer="crochet" };
// t_buffer personalization_string_c = { .length=8,  .buffer="knitting" };
// t_buffer personalization_string_d = { .length=7,  .buffer="tatting" };
//
// unsigned char random_buff[RANDOM_BUFFSIZE];
// t_buffer random = { .length=RANDOM_BUFFSIZE, .buffer=random_buff };
//
// t_sp800_90a_ctr_aes256_drbg_state rng_a;
// int result;
//
//void print_error(int errcode) {
//    switch(errcode) {
//        case RNG_STATUS_SUCCESS:
//            fprintf(stderr,"Errror 0x%08X : RNG_STATUS_SUCCESS\n",RNG_STATUS_SUCCESS);
//            break;
//        case RNG_STATUS_ERROR_INVALID_PARAMETERS:
//            fprintf(stderr,"Errror 0x%08X : RNG_STATUS_ERROR_INVALID_PARAMETERS\n",errcode);
//            break;
//        case RNG_STATUS_ERROR_NOISE_UNAVAILABLE:
//            fprintf(stderr,"Errror 0x%08X : RNG_STATUS_ERROR_NOISE_UNAVAILABLE\n",errcode);
//            break;
//        case RNG_STATUS_ERROR_RESEED_REQUIRED:
//            fprintf(stderr,"Errror 0x%08X : RNG_STATUS_ERROR_RESEED_REQUIRED\n",errcode);
//            break;
//        default:
//            fprintf(stderr,"Errror 0x%08X : RNG ERROR - UNKNOWN ERROR CODE?!\n",errcode);
//            break;
//    }
//}
//void print_hex(t_buffer *data) {
//  for(i=0; i < data->length, i++) {
//      printf("%02X",data->buffer[i]);
//      if ((i > 0) && ((i % 16) ==0)) printf("\n");
//  }
//  if ((i>0) && ((i%16) != 0)) printf("\n");
//}
//
// result = rng_command(RNG_CMD_INSTATIATE,NO_FLAGS,(t_buffer *)0,personalization_string_a, (t_buffer *)0,&rng_a);
// if (result!=RNG_STATUS_SUCCESS) {
//     printerror(result);
//     exit(-1);
// }
//
// result = rng_command(RNG_CMD_GENERATE,PREDICTION_RESISTANCE_REQ,(t_buffer *)0,(t_buffer *)0, random,&rng_a);
// if (result!=RNG_STATUS_SUCCESS) {
//     printerror(result);
//     exit(-1);
// }
// 
// printhex(random); 
// exit(0);
//

