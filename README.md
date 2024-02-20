# Adaptive attack against FESTA PKE protocol

A  implementation of adaptive attack against FESTA, accompanying the research paper '"An Efficient Adaptive Attack Against FESTA".

## Requirements

**SageMath version**: This code was developed and tested using SageMath version 10.1

**OAEP transform**: FESTA uses `SHAKE` imported from `pycryptodome` to extract random bytes. This can be installed using: 

```
sage -pip install -r requirements.txt
```

## FESTA PKE protocol  (written by Basso et al.)

If you want to play around with FESTA protocol itself, you can use the file `example_festa.sage` with the following arguments:

```
sage example_festa.sage [--128, --192, --256, --toy, --circulant]
```

- By default, the 128-bit security parameters are selected. To access other parameters:
  - The flag `--192` selects the parameters aiming for 192-bit security 
  - The flag `--256` selects the parameters aiming for 256-bit security 
  - The flag `--toy` selects small toy parameters suitable for debugging
- By default, the masking matrices are diagonal, unitary, invertible matrices.
  - The flag `--circulant` selected the matrices to be circulant, unitary, invertible matrices instead.

## Exception time  (written by us)

If you want to record the running time of two exceptions on your machine, you can use the file `exception_time.py` with the following argument:

```
sage exception_time.py [n, --128, --192, --256]
```

- By default, we record the exceptions repeated 5 times. To access other parameters:
  - The flag `n` specifies the number of repetitions.
- By default, we record the running time of exceptions in FESTA_128 (FESTA with 128-bit security). To access other parameters:
  - The flag `--192` records the time in FESTA_192.
  - The flag `--256` records the time in FESTA_256.

#### Example Output

```
User: % sage exception_time.py
================================================================================
                              Keygen successfully!
================================================================================
================================================================================
                             Encrypt successfully!
================================================================================
================================================================================
                    Running time of exceptions in FESTA_128:
================================================================================
                  exception 1: 6.768s,  exception 2: 10.540s.
                  exception 1: 6.634s,  exception 2: 10.463s.
                  exception 1: 6.658s,  exception 2: 10.479s.
                  exception 1: 6.704s,  exception 2: 10.545s.
                  exception 1: 6.648s,  exception 2: 10.345s.
================================================================================
  Average time of exception 1: 6.682s,  average time of exception 2: 10.474s.
================================================================================
```

## Adaptive attack against FESTA  (written by us)

If you want to recover the secret matrix of FESTA, you can use the file `attack_festa.sage` with the following arguments:

```
sage attack_festa.sage [n, --128, --192, --256, --basetime]
```

- By default, 10 bits of secret matirx will be recovered.
  - The flag `n` specifies the number of bits to recover, it should be smaller than b/2.
- By default, the FESTA_128 will be attacked. To access other parameters:
  - The flag `--192` attacks FESTA_192 
  - The flag `--256` attacks FESTA_256
- By default, the verification oracle is constructed through catching 'ValueError'.
  - The flag `--basetime` uses the verification oracle based on running time

#### Example Output

```
User: % sage attack_festa.sage
================================================================================
                              Keygen successfully!
================================================================================
================================================================================
                              Encrypt successfully!
================================================================================
================================================================================
                             Begin attack FESTA_128:
================================================================================
                                a_0 = 1, b_0 = 0
                             guess a_1 = 0, b_1 = 0
                                a_2 = 0, b_2 = 1
                                a_3 = 1, b_3 = 0
                                a_4 = 0, b_4 = 0
                                a_5 = 1, b_5 = 0
                                a_6 = 1, b_6 = 0
                                a_7 = 1, b_7 = 0
                                a_8 = 0, b_8 = 1
                                a_9 = 1, b_9 = 1
================================================================================
           Successfully recover 10 bits of secret matrix in 98.040s!
================================================================================
```


**Note**: Using a single performance core of an AMD Ryzen 7 7840H CPU, clocked at 3.8 GHz.
