// SP800-90A AES-256 CTR DRBG 
// dj.johnston@intel.com

#include "sp800_90a_ctr_aes256_drbg.h"
#include "aes256k128d.h"
#include <string.h>
#include <unistd.h>

//#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif

#ifndef __linux__
int check_cpuid() {
unsigned long long int do_we_have_cpuid;


    
asm("\n\
    pushfq\n\
    pop %%rax\n\
    movq %%rax,%%rbx\n\
    xor 0x00200000,%%rax\n\
    push %%rax\n\
    popfq\n\
    pushfq\n\
    pop %%rax\n\
    cmp %%rbx,%%rax\n\
    jz  nocpuid\n\
    push %%rbx\n\
    popfq\n\
    movq 1,%0\n\
    jmp endcheckcpuid\n\
nocpuid:\n\
    movq 0,%0\n\
endcheckcpuid:\n\
    nop":"=r"(do_we_have_cpuid)::"%rax","%rbx");
    if (do_we_have_cpuid == 1) return 1;
    return 0;
};

void get_cpuid(int leaf, unsigned int *eax,unsigned int *ebx,unsigned int *ecx,unsigned int *edx) {
unsigned int a;
unsigned int b;
unsigned int c;
unsigned int d;

asm("\n\
    mov %4, %%eax\n\
    cpuid\n\
    mov %%eax,%0\n\
    mov %%ebx,%1\n\
    mov %%ecx,%2\n\
    mov %%edx,%3":"=r"(a),"=r"(b),"=r"(c),"=r"(d):"r"(leaf):"%eax","%ebx","%ecx","%edx");
    *eax = a;
    *ebx = b;
    *ecx = c;
    *edx = d;
}

int check_is_intel() {

   unsigned int eax,ebx,ecx,edx;
   get_cpuid(0,&eax,&ebx,&ecx,&edx);

    if( memcmp((char *)(&ebx), "Genu", 4) == 0 &&
        memcmp((char *)(&edx), "ineI", 4) == 0 &&
        memcmp((char *)(&ecx), "ntel", 4) == 0) {
            return 1;
    }
    return 0;
}

int check_is_amd() {

   unsigned int eax,ebx,ecx,edx;
   get_cpuid(0,&eax,&ebx,&ecx,&edx);

    if( memcmp((char *)(&ebx), "Auth", 4) == 0 &&
		memcmp((char *)(&edx), "enti", 4) == 0 &&
		memcmp((char *)(&ecx), "cAMD", 4) == 0) {
			return 1;
	}
    return 0;
}

int check_rdrand() {
   unsigned int eax,ebx,ecx,edx;
   get_cpuid(1,&eax,&ebx,&ecx,&edx);
   
   if ((ecx & 0x40000000)==0x40000000) return 1;
   return 0;
}

int check_rdseed() {
   unsigned int eax,ebx,ecx,edx;
   get_cpuid(7,&eax,&ebx,&ecx,&edx);
   
   if ((ebx & 0x00040000)==0x00040000) return 1;
   return 0;
   
}

int rdrand_rdseed_check_support(t_sp800_90a_ctr_aes256_drbg_state *state)
{
    
    #ifdef DEBUG
    unsigned int eax,ebx,ecx,edx;
    char dstring[6];

    dstring[0] = (char)0;
    dstring[1] = (char)0;
    dstring[2] = (char)0;
    dstring[3] = (char)0;
    dstring[4] = (char)0;
    dstring[5] = (char)0;
    #endif
   
    if (check_is_intel() || check_is_amd()) {
        if (check_rdrand())
            state->rdrand = 1;
        else
            state->rdrand = 0;
        
        if (check_rdseed())
            state->rdseed = 1;
        else
            state->rdseed = 0;
        
        // If we have either RdRand or RdSeed we can continue
        if ((state->rdrand==1) ||(state->rdseed==1)) {
            return RNG_STATUS_SUCCESS;
        }
        // Otherwise not
        return RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE;
        
    } else { // Else we don't appear to be an intel or amd cpu
        state->rdrand = 0;
        state->rdseed = 0;
            #ifdef DEBUG
            get_cpuid(0,&eax,&ebx,&ecx,&edx);
            memcpy(dstring,(char *)&ebx,4);
            printf(" CPUID 0,0 EBX = %s",dstring);
            memcpy(dstring,(char *)&edx,4);
            printf(" CPUID 0,0 EDX = %s",dstring);
            memcpy(dstring,(char *)&ecx,4);
            printf(" CPUID 0,0 ECX = %s",dstring);
            #endif
        return RNG_STATUS_ERROR_NOT_INTEL;
    }

    // We should not get here
    return RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE;
}
#else
typedef struct {
        unsigned int EAX;
        unsigned int EBX;
        unsigned int ECX;
        unsigned int EDX;
} CPUIDinfo;

// RdRand Access Functions
typedef unsigned int DWORD;

void _CPUID(CPUIDinfo *info, const unsigned int func, const unsigned int subfunc)
{
asm(".intel_syntax noprefix\n");
asm("mov r8, rdi\n");
asm("mov r9, rsi\n");
asm("mov r10, rdx\n");
asm("push rax\n");
asm("push rbx\n");
asm("push rcx\n");
asm("push rdx\n");
asm("mov eax, r9d\n");
asm("mov ecx, r10d\n");
asm("cpuid;\n");
asm("mov DWORD PTR [r8], eax\n");
asm("mov DWORD PTR [r8+4], ebx\n");
asm("mov DWORD PTR [r8+8], ecx\n");
asm("mov DWORD PTR [r8+12], edx\n");
asm("pop rdx\n");
asm("pop rcx\n");
asm("pop rbx\n");
asm("pop rax\n");
asm(".att_syntax prefix\n");
}

int rdrand_rdseed_check_support(t_sp800_90a_ctr_aes256_drbg_state *state)
{
    unsigned int j;
    DWORD maxCPUID;
    CPUIDinfo info;
    int got_intel_cpu=0;

    #ifdef DEBUG
    char dstring[6];
    
    dstring[0] = (char)0;
    dstring[1] = (char)0;
    dstring[2] = (char)0;
    dstring[3] = (char)0;
    dstring[4] = (char)0;
    dstring[5] = (char)0;
    #endif
    
    _CPUID(&info,0,0);
    if(memcmp((char *)(&info.EBX), "Genu", 4) == 0 &&
        memcmp((char *)(&info.EDX), "ineI", 4) == 0 &&
        memcmp((char *)(&info.ECX), "ntel", 4) == 0) {
        
        // Check for RdRand
        _CPUID(&info,1,0);
        if ((info.ECX & 0x40000000)==0x40000000) {
            state->rdrand=1;
        } else {
            state->rdrand=0;
        }

        // Check for RdSeed
        _CPUID(&info,7,0);
        if ((info.EBX & 0x00040000)==0x00040000) {
            state->rdseed=1;
        } else {
            state->rdseed=0;
        }

        // If we have either RdRand or RdSeed we can continue
        if ((state->rdrand==1) ||(state->rdseed==1)) {
            return RNG_STATUS_SUCCESS;
        } else {
            return RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE;
        }
    }
    else { // We don't have an intel CPU
        #ifdef DEBUG
            memcpy(dstring,&info.EBX,4);
            printf(" CPUID 0,0 EBX = %s",dstring);
            memcpy(dstring,&info.EDX,4);
            printf(" CPUID 0,0 EDX = %s",dstring);
            memcpy(dstring,&info.ECX,4);
            printf(" CPUID 0,0 ECX = %s",dstring);
        #endif
        return RNG_STATUS_ERROR_NOT_INTEL;
    }
    return RNG_STATUS_ERROR_RDRAND_RDSEED_NOT_AVAILABLE;
}
#endif

/****************************************/
/* aes128k128d()                        */
/* Performs a 128 bit AES encrypt with  */
/* 128 bit data.                        */
/****************************************/
void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
    int i;
    for (i=0;i<16; i++)
    {
        out[i] = a[i] ^ b[i];
    }
}

/**********************************************/
/* Gets a 64 bits random number using RDRAND  */
/*   Writes that to *therand.                 */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

int rdrand64_step(unsigned long long int *therand)
{
unsigned long long int foo;
int cf_error_status;
asm("\n\
        rdrand %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
        *therand = foo;
return cf_error_status;
}

/**********************************************/
/* Gathers 64 bits of entropy through RDSEED  */
/*   Writes that entropy to *therand.         */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

int rdseed64_step(unsigned long long int *therand)
{
unsigned long long int foo;
int cf_error_status;
asm("\n\
        rdseed %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
        *therand = foo;
return cf_error_status;
}

/****************************************************************/
/* Uses RdRand to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long int *)dest[0+]. */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

int rdrand_get_n_qints_retry(unsigned int n, unsigned int retry_limit, unsigned long long int *dest)
{
int success;
int count;
unsigned long long int qrand;
unsigned int i;

    for (i=0; i<n; i++)
    {
        count = 0;
        do
        {
                success=rdrand64_step(dest);
        } while((success == 0) && (count++ < retry_limit));
        if (success == 0) return 0;
        dest=&(dest[1]);
    }
    return 1;
}

/****************************************************************/
/* Uses RdSeed to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long int *)dest[0+]. */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

int rdseed_get_n_qints_retry(unsigned int n, unsigned int retry_limit, unsigned long long int *dest)
{
int success;
int count;
unsigned long long int qrand;
unsigned int i;

    for (i=0; i<n; i++)
    {
        count = 0;
        do
        {
                success=rdseed64_step(dest);
        } while((success == 0) && (count++ < retry_limit));
        if (success == 0) return 0;
        dest=&(dest[1]);
    }
    return 1;
}

/************************************************************************************/
/* CBC-MAC together 2048 128 bit values, to exceed the reseed limit, to guarantee   */
/* some interveneing reseeds.                                                       */
/* Creates a random value that is fully forward and backward prediction resistant,  */
/* suitable for seeding a NIST SP800-90 Compliant, FIPS 1402-2 certifiable SW DRBG  */
/************************************************************************************/

int rdrand_get_seed384(void *buffer)
{
    unsigned char m[16];
    unsigned char key[32];
    unsigned char ffv[16];
    unsigned char xored[16];
    unsigned int i;
    unsigned int retry_limit;

    retry_limit = 10;

    for (i=0;i<32;i++)
    {
        key[i]=(unsigned char)i;
    }
    for (i=0;i<16;i++)
    {
        ffv[i]=0;
    }

    for (i=0; i<2048;i++)
    {
        if(rdrand_get_n_qints_retry(2,retry_limit,(unsigned long long int*)m) == 0) return 0;
        xor_128(m,ffv,xored);
        aes256k128d(key,xored,ffv);
    }
    for (i=0;i<16;i++) ((unsigned char *)buffer)[i] = ffv[i];

    for (i=0; i<2048;i++)
    {
        if(rdrand_get_n_qints_retry(2,retry_limit,(unsigned long long int*)m) == 0) return 0;
        xor_128(m,ffv,xored);
        aes256k128d(key,xored,ffv);
    }
    for (i=0;i<16;i++) ((unsigned char *)buffer)[i+16] = ffv[i];

    for (i=0; i<2048;i++)
    {
        if(rdrand_get_n_qints_retry(2,retry_limit,(unsigned long long int*)m) == 0) return 0;
        xor_128(m,ffv,xored);
        aes256k128d(key,xored,ffv);
    }
    for (i=0;i<16;i++) ((unsigned char *)buffer)[i+32] = ffv[i];

    return 1;
}

/*********************************************/
/* Get 384 bits of full entropy using RdSeed */
/*********************************************/

int rdseed_get_seed384(void *buffer)
{
    int retry_limit;

    retry_limit=10000;

    if (rdseed_get_n_qints_retry(6,retry_limit,(unsigned long long int*)buffer) == 0) return 0;
    return 1;
}

/*********************************************/
/* GetEntropy() function                     */
/* First tries RdSeed, then tries RdRand     */
/* RdRand data is CBC-MACed to condition it  */
/* to full entropy.
/*********************************************/

int rng_get_entropy(t_buffer *buffer,t_sp800_90a_ctr_aes256_drbg_state *state) {
    if (buffer->length != 48) {
        return RNG_STATUS_ERROR_INVALID_PARAMETERS;
    }
    else {
        if (state->rdseed == 1) {
            if (rdseed_get_seed384((void *)buffer->buffer) == 1) return RNG_STATUS_SUCCESS;
        }
        if (state->rdrand ==1) {
            if (rdrand_get_seed384((void *)buffer->buffer) == 1) return RNG_STATUS_SUCCESS;
        }
    } 
        
    return RNG_STATUS_ERROR_NOISE_UNAVAILABLE;
}

/*********************************************/
/* GetNoise() function                       */
/* First tries RdSeed, then tries RdRand     */
/*********************************************/

int rng_get_noise(unsigned char *buffer, unsigned int num_of_bytes, t_sp800_90a_ctr_aes256_drbg_state *state) {
    int qints;
    qints = num_of_bytes/8;
    if ((num_of_bytes % 8)!=0) return RNG_STATUS_ERROR_INVALID_PARAMETERS;

    if (state->rdseed==1) {
        if (rdseed_get_n_qints_retry(qints, 10000, (unsigned long long int *)buffer) == 1) return RNG_STATUS_SUCCESS;
    }
    if (state->rdrand==1) {
        if (rdrand_get_n_qints_retry(qints, 10, (unsigned long long int *)buffer) == 1) return RNG_STATUS_SUCCESS;
    }
 
    return RNG_STATUS_ERROR_NOISE_UNAVAILABLE;
}

// Low Level Functions
//

int ctr_aes_256_drbg_update(unsigned char *provided_data, unsigned int provided_data_length, t_sp800_90a_ctr_aes256_drbg_state* state) {
    unsigned int ctr;
    unsigned char *ctrptr;
    unsigned char newkey_h[16];
    unsigned char newkey_l[16];
    unsigned char new_v[16];
    unsigned int i;
    
    ctrptr = (unsigned char *)&ctr;
    
    // Little to big endian conversion for counter, because SP800-90A is stoopid.
    
    ctrptr[0]=state->vector128[15];
    ctrptr[1]=state->vector128[14];
    ctrptr[2]=state->vector128[13];
    ctrptr[3]=state->vector128[12];
    ctr = ctr + 1;
    state->vector128[15]=ctrptr[0];
    state->vector128[14]=ctrptr[1];
    state->vector128[13]=ctrptr[2];
    state->vector128[12]=ctrptr[3];
    
    aes256k128d(state->key256, state->vector128, newkey_l);
    
    //#ifdef DEBUG
    //printf(" ctr = ");
    //for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" aesout = ");
    //for(i=0;i<16;i++) printf("%02X",newkey_l[i]);
    //printf("\n");
    //#endif
    
    ctrptr[0]=state->vector128[15];
    ctrptr[1]=state->vector128[14];
    ctrptr[2]=state->vector128[13];
    ctrptr[3]=state->vector128[12];
    ctr = ctr + 1;
    state->vector128[15]=ctrptr[0];
    state->vector128[14]=ctrptr[1];
    state->vector128[13]=ctrptr[2];
    state->vector128[12]=ctrptr[3];
    
    aes256k128d(state->key256, state->vector128, newkey_h);
    
    //#ifdef DEBUG
    //printf(" ctr = ");
    //for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" aesout = ");
    //for(i=0;i<16;i++) printf("%02X",newkey_h[i]);
    //printf("\n");
    //#endif
    
    ctrptr[0]=state->vector128[15];
    ctrptr[1]=state->vector128[14];
    ctrptr[2]=state->vector128[13];
    ctrptr[3]=state->vector128[12];
    ctr = ctr + 1;
    state->vector128[15]=ctrptr[0];
    state->vector128[14]=ctrptr[1];
    state->vector128[13]=ctrptr[2];
    state->vector128[12]=ctrptr[3];
    aes256k128d(state->key256, state->vector128, new_v);
    
    //#ifdef DEBUG
    //printf(" ctr = ");
    //for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" aesout = ");
    //for(i=0;i<16;i++) printf("%02X",new_v[i]);
    //printf("\n");
    //#endif
    
    if (provided_data_length > 15) {
        for (i=0; i<16;i++) newkey_l[i]=newkey_l[i] ^ provided_data[i];
    }    
    if (provided_data_length > 31) {
        for (i=0; i<16;i++) newkey_h[i]=newkey_h[i] ^ provided_data[i+16];
    }
    if (provided_data_length > 47) {
        for (i=0; i<16;i++) new_v[i]=new_v[i] ^ provided_data[i+32];
    }

    for (i=0;i<16;i++) state->key256[i] = newkey_l[i];
    for (i=0;i<16;i++) state->key256[i+16] = newkey_h[i];
    for (i=0;i<16;i++) state->vector128[i] = new_v[i];
    
    // Erase state on stack.
    ctr = 0;
    ctrptr = 0;
    for (i=0;i<16;i++) {
        newkey_h[i] = (unsigned char)0;
        newkey_l[i] = (unsigned char)0;
        new_v[i] = (unsigned char)0;
    }
    i = 0;

    return RNG_STATUS_SUCCESS;
}

int ctr_aes_256_drbg_instantiate(
            unsigned char *entropy_input,unsigned int entropy_input_length,
            unsigned char *personalization_string, unsigned int personalization_string_length,
            t_sp800_90a_ctr_aes256_drbg_state* state) {

    unsigned int i;
    unsigned char seed[48];
    unsigned int result;
 
    if (entropy_input_length != 48) return RNG_STATUS_ERROR_INVALID_PARAMETERS; 
    // Personalization string must be 384 bits (48 bytes) as per SP800-90A_r1 10.2.1.3.1

    //result = rdrand_rdseed_check_support(state);
    //if (result != RNG_STATUS_SUCCESS) return result;

    // Setting pointless instance variables that the spec asks for.
    state->security_strength = 256;
    state->prediction_resistance = 1;

    #ifdef DEBUG
    //printf("INSTANTI ");
    if (entropy_input_length > 0) {
        printf("EntropyInput = ");
        for(i=0;i<entropy_input_length;i++) printf("%02X",entropy_input[i]);
    }
    if (personalization_string != 0) {
        if (personalization_string_length > 0) {
            printf("PersonalizationString = ");
            for(i=0;i<personalization_string_length;i++) printf("%02X",personalization_string[i]);
        }
    }

    printf("\n");
    #endif

    if (personalization_string_length == 48) {
        for (i=0;i<48;i++) seed[i] = entropy_input[i] ^ personalization_string[i];
    }
    else {
        for (i=0;i<48;i++) seed[i] = entropy_input[i];
    }
    for (i=0;i<16;i++) state->vector128[i]=(unsigned char)0;
    for (i=0;i<32;i++) state->key256[i]=(unsigned char)0;
    
    ctr_aes_256_drbg_update(seed, 48, state);
    state->c = 1;
    state->prediction_resistance = 1;
    state->reseed_interval = 1024;

    #ifdef DEBUG
    printf("** INSTANTIATE:\n");
    printf("    Key = ");
    for(i=0;i<32;i++) printf("%02X",state->key256[i]);
    printf("\n    V   = ");
    for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" C = %d", state->c);
    printf("\n"); 
    #endif

    // Erase state on stack.
    for (i=0;i<48;i++) seed[i] = (unsigned char)0;
    i = 0;
    return RNG_STATUS_SUCCESS;
}

int ctr_aes_256_drbg_uninstantiate(t_sp800_90a_ctr_aes256_drbg_state* state) {

    unsigned int i;
    
    //#ifdef DEBUG
    //printf("UNINSTANTIATE ");
    //printf("\n");
    //#endif

   // Personalization string must be 384 bits (48 bytes) as per SP800-90A_r1 10.2.1.3.1
   
    for (i=0;i<16;i++) state->vector128[i]=(unsigned char)0;
    for (i=0;i<32;i++) state->key256[i]=(unsigned char)0;
    state->c = 1;

    //#ifdef DEBUG
    //printf("UNINSTANTIATE RETURN:   K = ");
    //for(i=0;i<32;i++) printf("%02X",state->key256[i]);
    //printf(" V = ");
    //for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" C = %d", state->c);
    //printf("\n"); 
    //#endif
    
    // Erase state on stack.
    i = 0;
    return RNG_STATUS_SUCCESS;
}

int ctr_aes_256_drbg_reseed(
            unsigned char *entropy_input,unsigned int entropy_input_length,
            unsigned char *additional_input,unsigned int additional_input_length,
            t_sp800_90a_ctr_aes256_drbg_state* state) {
    
    unsigned int i;
    unsigned char seed[48];
    
    #ifdef DEBUG
    //printf("RESEED ");
    if (entropy_input_length > 0) {
        printf("\nEntropyInputReseed = ");
        for(i=0;i<entropy_input_length;i++) printf("%02X",entropy_input[i]);
    }
    if (additional_input_length > 0) {
        printf("AdditionalInputReseed = ");
        for(i=0;i<additional_input_length;i++) printf("%02X",additional_input[i]);
    }

    printf("\n"); 
    #endif

    if ((entropy_input_length==48) && (additional_input_length==48)) {
        for (i=0;i<48;i++) seed[i] = entropy_input[i] ^ additional_input[i];
    }
    else {
        for (i=0;i<48;i++) seed[i] = entropy_input[i];
    }
    ctr_aes_256_drbg_update(seed, 48, state);
    state->c = 1;

    #ifdef DEBUG
    printf("** RESEED\n");
    printf("    Key = ");
    for(i=0;i<32;i++) printf("%02X",state->key256[i]);
    printf("\n    V   = ");
    for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" C = %d", state->c);
    printf("\n"); 
    //printf("\n"); 
    #endif
    
    // Erase state on stack.
    for (i=0;i<48;i++) seed[i] = (unsigned char)0;
    i = 0;
    return RNG_STATUS_SUCCESS;
}

int ctr_aes_256_drbg_generate(
            unsigned int gen_len, 
            unsigned char *output,
            t_sp800_90a_ctr_aes256_drbg_state* state) {
    //#ifdef DEBUG
    //unsigned int j;
    //#endif
    unsigned int requested_blocks;
    unsigned int i;
    unsigned int j;
    unsigned int ctr;
    unsigned char *ctrptr;
    unsigned char buffer_stage[16];
    unsigned int output_position;

    ctrptr = (unsigned char *)&ctr;
    
    #ifdef DEBUG
    printf("** GENERATE\n");
    #endif

    requested_blocks = gen_len/16;
    if ((gen_len % 16) != 0) requested_blocks++;

    if ((state->c) >= (state->reseed_interval)) {
        return CTR_AES256_DRBG_ERR_RESEED_REQUIRED;
    }
   
    output_position=0;
 
    for (i=0;i<requested_blocks;i++) {
    
        ctrptr[0]=state->vector128[15];
        ctrptr[1]=state->vector128[14];
        ctrptr[2]=state->vector128[13];
        ctrptr[3]=state->vector128[12];
        ctr = ctr + 1;
        state->vector128[15]=ctrptr[0];
        state->vector128[14]=ctrptr[1];
        state->vector128[13]=ctrptr[2];
        state->vector128[12]=ctrptr[3];
        
        aes256k128d(state->key256, state->vector128, buffer_stage);
        for (j=0;j<16;j++) {
            if (output_position < gen_len) output[output_position++] = buffer_stage[j];
            else break;
        }
    }
    state->c = state->c + 1;

    //#ifdef DEBUG
    //printf("GENERATE Return   K = ");
    //for(i=0;i<32;i++) printf("%02X",state->key256[i]);
    //printf(" V = ");
    //for(i=0;i<16;i++) printf("%02X",state->vector128[i]);
    //printf(" C = %d", state->c);
    //printf("\n"); 
    //#endif

    // Erase state on stack.
    ctr = 0;
    ctrptr = 0;
    for (i=0;i<16;i++) buffer_stage[i] = 0;
    requested_blocks = 0;
 
    return RNG_STATUS_SUCCESS;
}

/*********************************************/
/* RNG Service Functions                     */
/* These link the noise source to the        */
/* deterministic functions and preset        */
/* an interface upwards to the command       */
/* interface.                                */
/********************************************/

// rng_svc_instantiate().
// Performs the SP800-90A CTR-DRBG withouut df instantiate function
// Using 384 bits of entropy from RdRand or RdSeed

unsigned int rng_svc_instantiate(t_buffer *personalization_string, t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;
    unsigned char entropy_buffer[48];
    t_buffer entropy;

    entropy.buffer = entropy_buffer;
    entropy.length = 48;
    
    result = rng_svc_initialize_entropy_source(rng_instance);
    if (result != RNG_STATUS_SUCCESS) return result;
    
    result = rng_get_entropy(&entropy, rng_instance);
    if (result != RNG_STATUS_SUCCESS) return result;

    if (personalization_string == 0) {
        result = ctr_aes_256_drbg_instantiate(entropy.buffer, entropy.length,
                                          0,0,
                                          rng_instance);
    }
    else {            
        result = ctr_aes_256_drbg_instantiate(entropy.buffer, entropy.length,
                                          personalization_string->buffer, personalization_string->length,
                                          rng_instance);
    }
    return result;
}

unsigned int rng_svc_uninstantiate(t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;

    result = ctr_aes_256_drbg_uninstantiate(rng_instance);
    return result;
}

unsigned int rng_svc_reseed(t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;
    unsigned char entropy_buffer[48];
    t_buffer entropy;

    entropy.buffer = entropy_buffer;
    entropy.length = 48;

    result = rng_get_entropy(&entropy, rng_instance);
    if (result != RNG_STATUS_SUCCESS) return result;
  
    result = ctr_aes_256_drbg_reseed(entropy.buffer, entropy.length, 0,0, rng_instance);
    return result; 
}

unsigned int rng_svc_generate(t_buffer *destination, unsigned int flags,  t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;
    unsigned int gen_len;
    gen_len = destination->length;

    if (rng_instance->c >= rng_instance->reseed_interval) {
        result = rng_svc_reseed(rng_instance); 
        if (result != RNG_STATUS_SUCCESS) return result; 
    }

    result = ctr_aes_256_drbg_generate(gen_len, destination->buffer, rng_instance);
    if (result !=  RNG_STATUS_SUCCESS) return result;

    result = ctr_aes_256_drbg_update(0,0,rng_instance);
    if (result !=  RNG_STATUS_SUCCESS) return result;

    if ((flags | PREDICTION_RESISTANCE_REQ) == PREDICTION_RESISTANCE_REQ) {
        result = rng_svc_reseed(rng_instance); 
        return result; 
    }
    return RNG_STATUS_SUCCESS; 
}

/********************************************/
/* Set up the entropy source                */
/********************************************/

unsigned int rng_svc_initialize_entropy_source(t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;

    // Check RdRand or RdSeed is available for an entropy source
    result = rdrand_rdseed_check_support(rng_instance);
    if (result != RNG_STATUS_SUCCESS) return result;
    
    return result; 
}
    
/********************************************/
/* A pass through for get_noise to maintain */
/* the layer separation.                    */
/********************************************/

unsigned int rng_svc_get_noise(t_buffer *destination, t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;

    result = rng_get_noise(destination->buffer, destination->length, rng_instance);
    return result; 
}

/**********************************************/
/* A pass through for get_entropy to maintain */
/* the layer separation.                      */
/**********************************************/

unsigned int rng_svc_get_entropy(t_buffer *destination, t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {
    unsigned int result;

    result = rng_get_entropy(destination, rng_instance);
    return result; 
}

// RNG Command Function

int rng_command(unsigned int command, unsigned int flags, t_buffer *additional_input, t_buffer *personalization_string,t_buffer *destination, t_sp800_90a_ctr_aes256_drbg_state *rng_instance) {

    int result;
    int result2;
    int gen_len;
    int requested_blocks;
    
    #ifdef DEBUG
    printf("Got Command %08x\n",command);
    #endif    
    
    switch(command) {

        case(RNG_CMD_INSTANTIATE):
            result = rng_svc_instantiate(personalization_string, rng_instance); 
            if (result != RNG_STATUS_SUCCESS) return result;
            break;
        case(RNG_CMD_UNINSTANTIATE):
            result = ctr_aes_256_drbg_uninstantiate(rng_instance);
            return result;
            break;
        case(RNG_CMD_GENERATE):
            result = rng_svc_generate(destination, flags,  rng_instance);
            return result; 
            break;
        case(RNG_CMD_RESEED):
            result = rng_svc_reseed(rng_instance);
            return result;
            break;    
        case(RNG_CMD_GETNOISE):
            result = rng_get_noise(destination->buffer, destination->length, rng_instance);
            return result;
            break;    
        default:
            return RNG_STATUS_ERROR_UNKNOWN_COMMAND;
            break;
    }
    return result;
}






