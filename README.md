# gizakey
A C command line program to generate a 256 bit full entropy key using rdrand or rdseed as the source, with an SP800-90A and B compliant entropy source and DRBG.

## To build on Linux
```
  make$ make
  gcc  -maes -mrdrnd -mrdseed gizakey.c aes_ni_intrinsics_256k.c sp800_90a_ctr_aes256_drbg.c -o gizakey
```

## To install
```
  $ sudo make install
  cp gizakey /usr/local/bin
```

## To run
```
  $ gizakey > key.bin
  GIZAKEY : RNG_CMD_INSTANTIATE
  RNG_STATUS_SUCCESS
  GIZAKEY : RNG_CMD_GENERATE with PREDICTION RESISTANCE
  RNG_STATUS_SUCCESS
  GIZAKEY : Outputting binary 256 bit key to stout
  GIZAKEY : ZEROIZE
  GIZAKEY: RNG_CMD_UNINSTANTIATE
  RNG_STATUS_SUCCESS
```

## To look at the output key
```
  $ od -x key.bin
  0000000 e51a d8bf 0321 68f7 484e 4e56 e0bf ecd8
  0000020 dc00 bdd1 3c9a e1b0 feb7 c9b2 ad36 a282
  0000040
  
  

