/**************************************************/
/* gizakey - Generate a 256 bit, full entropy key */
/* David Johnston. dj.johnston@intel.com          */
/**************************************************/


#include <stdio.h>
#include "sp800_90a_ctr_aes256_drbg.h"

unsigned char output[1024];

t_sp800_90a_ctr_aes256_drbg_state state;

void print_error(unsigned int result) {
    if (result ==  RNG_STATUS_SUCCESS) fprintf(stderr,"RNG_STATUS_SUCCESS\n");
    else if (result ==  RNG_STATUS_ERROR_INVALID_PARAMETERS) fprintf(stderr,"RNG_STATUS_ERROR_INVALID_PARAMETERS\n");
    else if (result ==  RNG_STATUS_ERROR_NOISE_UNAVAILABLE) fprintf(stderr,"RNG_STATUS_ERROR_NOISE_UNAVAILABLE\n");
    else if (result ==  RNG_STATUS_ERROR_RESEED_REQUIRED) fprintf(stderr,"RNG_STATUS_ERROR_RESEED_REQUIRED\n");
    else if (result ==  RNG_STATUS_ERROR_UNKNOWN_COMMAND) fprintf(stderr,"RNG_STATUS_ERROR_UNKNOWN_COMMAND\n");
    else if (result ==  RNG_STATUS_ERROR_NOT_INTEL) fprintf(stderr,"RNG_STATUS_ERROR_NOT_INTEL\n");
    else if (result ==  RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE) printf("RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE\n");
    else fprintf(stderr,"UNKNOWN ERROR\n");
}

int main() {
    int i;
    unsigned int result;
    unsigned char output_buf[256];
    t_sp800_90a_ctr_aes256_drbg_state rng_instance;
    t_buffer output;

    output.buffer = output_buf;
    output.length = 256;
    fprintf(stderr,"GIZAKEY : RNG_CMD_INSTANTIATE\n");
    result = rng_command(RNG_CMD_INSTANTIATE,NO_FLAGS,0,0,0,&rng_instance);
    if (result != RNG_STATUS_SUCCESS) {
        print_error(result);
        return 0;
    }
    print_error(result);

    fprintf(stderr,"GIZAKEY : RNG_CMD_GENERATE with PREDICTION RESISTANCE\n");
    result = rng_command(RNG_CMD_GENERATE,PREDICTION_RESISTANCE_REQ,0,0,&output,&rng_instance);
    if (result != RNG_STATUS_SUCCESS) {
        print_error(result);
        return 0;
    }
    print_error(result);

    fprintf(stderr,"GIZAKEY : Outputting binary 256 bit key to stout\n");
    fwrite(&(output.buffer[256-32]), 1, 32, stdout);    
    
    //for (i=0;i<(32);i++) printf("%02X",output.buffer[(256-32)+i]);
    //printf("\n");

    
    fprintf(stderr,"GIZAKEY : ZEROIZE\n");
    
    for(i=0;i<256;i++) output.buffer=0x00;

    fprintf(stderr,"GIZAKEY: RNG_CMD_UNINSTANTIATE\n");
    result = rng_command(RNG_CMD_UNINSTANTIATE,NO_FLAGS,0,0,0,&rng_instance);
    if (result != RNG_STATUS_SUCCESS) {
        print_error(result);
        return 0;
    }
    print_error(result);
    return 1;

}

