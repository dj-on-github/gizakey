
all: gizakey

install:
	cp gizakey /usr/local/bin
clean:
	rm -f *.o
	rm -f gizakey

gizakey: gizakey.c aes_ni_intrinsics_256k.c sp800_90a_ctr_aes256_drbg.c
	gcc  -maes -mrdrnd -mrdseed gizakey.c aes_ni_intrinsics_256k.c sp800_90a_ctr_aes256_drbg.c -o gizakey



