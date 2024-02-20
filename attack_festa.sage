"""
To recover 10 bits of the secret matrix of FESTA with 128-bit security

```
sage attack_festa.sage
```

If you want to specify the number of bits to recover, run the file with the 'n' flag. For example:

```
sage attack_festa.sage 100
```

The attack against FESTA with higher security can be run with

```
sage attack_festa.sage [--128, --192, --256]
```

If you want to use the verification oralce based on running time, run the file with the '--basetime' flag.
For example:

```
sage attack_festa.sage --basetime
```
"""


import time
from festa import FESTA
from parameters.params import parameter_sets
from utilities.pairing import weil_pairing_pari
from utilities.discrete_log import windowed_pohlig_hellman
from utilities.utils import print_info, print_detail
from exception_time import average_time

global alice, bob, basetime, bits, intermediate_time

SECURITY = "128"
for arg in sys.argv[1:]:
    if arg.lower() in ["--192", "-II"]:
        SECURITY = "192"
    elif arg.lower() in ["--256", "-V"]:
        SECURITY = "256"

NAME = "FESTA_" + SECURITY

# Initialize Alice and Bob, where secret matrices are circulant.
params = parameter_sets[NAME]
alice = FESTA(params, diag=False)
bob   = FESTA(params, diag=False)

# Key-generation of alice
alice.keygen()
print_info('Keygen successfully!')

# Encryption of a random message
pk = alice.export_public_key()
m = randint(0, 2**alice.lambda_security - 1)
c = bob.encrypt(pk, m)
print_info('Encrypt successfully!')

b = alice.b
ct = alice.decompress_ciphertext(c)
E1, R1, S1, E2, R2, S2 = ct


# Our adaptive attack to recover bits of secret matrix.
# 
# Flag 'n' specifies the number of bits to recover, by default n = 10. Flag '--128', '--192', '--256'
# specifies which security level of FESTA to attack, by default attack FESTA_128. Flag '--basetime' 
# specifies the verification oracle based on running time, by default oracle bases on cathing 'ValueError'.

bits= 10
basetime = False
for arg in sys.argv[1:]:
    if arg.lower() in ["--basetime", "-t"]:
        basetime = True

        # compute the intermediate running time of exception 1 and exception 2. 
        intermediate_time = average_time(alice, bob, b, E1, R1, S1, E2, R2, S2)

    elif arg.isnumeric():
    	if 0 < int(arg) <= b/2:
    		bits = int(arg)
    	else:
    		print_detail('The number of bits to recover is illegal!')

SUCCESS = False

# This function implements the verification oracle in our paper. By default, it is constructed through
# catching 'ValueError'. Flag '--basetime' will specify the verification oracle based on running time.
def verification_oracle(E1, R1, S1, E2, R2, S2):
	ct_prime = (E1, R1, S1, E2, R2, S2)
	c_prime = bob.compress_ciphertext(ct_prime)

	if basetime:
		try:
			start = time.time()
			m2=alice.decrypt(c_prime)
		except ValueError:
			pass
		end = time.time()
		t = end - start
		return t > intermediate_time

	else:
		try:
			m_prime = alice.decrypt(c_prime)
			return 1
		except ValueError:
			return 0

# This function is an alternative of TorAtk algorithm to check the correctness of the recovered matrix.
# It is achieved by directly comparing recovered matrix and honest secret matrix.
def TorAtk_alternative(gamma,delta):
	A = alice.sk[0]
	if (gamma-A[0][0])%2^(bits)==0 and (delta-A[0][1])%2^(bits)==0:
		return 1
	elif (gamma+A[0][0])%2^(bits)==0 and (delta+A[0][1])%2^(bits)==0:
		return 1
	else:
		return 0


print_info('Begin attack ' + NAME + ':')
start = time.time()

# Recover the det of sceret matrix A using Weil pairing.
pair_E0 = weil_pairing_pari(alice.Pb, alice.Qb, 2^b)
pair_EA = weil_pairing_pari(alice.pk[1], alice.pk[2], 2^b)
det = (windowed_pohlig_hellman(pair_EA, pair_E0, b, alice.window)*inverse_mod(alice.dA,2^b))%2^b

# Initialize gamma and delta
gamma, delta = 0,0

# Recover the first bits of gamma and delta.
gamma = verification_oracle(E1, R1 + 2^(b-1) * S1, S1, E2, R2 + 2^(b-1) * S2, S2)
delta = 1 - gamma

print_detail('a_0 = %d, b_0 = %d' % (gamma,delta))

# disguss gamma is odd or even
if gamma==1:

	# recover b_1
	b_1 = 1 - verification_oracle(E1, R1 + 2^(b-2) * S1, S1, E2, R2 + 2^(b-2) * S2, S2)
	delta += 2*b_1

	# guess a1 = 0, recover ohter bits of gamma and delta
	print_detail('guess a_1 = 0, b_1 = %d' % b_1 )

	for i in range(2,bits):

		#recover a_i
		if (det - gamma^2 + delta^2)%2^(i+2) ==0:
			a_i = 0
		else:
			a_i = 1

		# recover b_i
		b_i = 1 - verification_oracle(E1, (1+2^(b-i-2)*delta)*R1 + 2^(b-i-1)*gamma * S1, (1-2^(b-i-2)*delta)*S1, E2, (1-2^(b-i-2)*delta)*R2 + 2^(b-i-1)*gamma * S2, (1+2^(b-i-2)*delta)*S2)

		gamma += a_i * 2^i
		delta += b_i * 2^i
		print_detail('a_%d = %d, b_%d = %d' % (i,a_i,i,b_i))

	if TorAtk_alternative(gamma, delta):
		end = time.time()
		cost = end - start
		SUCCESS = True
		print_info('Successfully recover %d bits of secret matrix in %.3fs!' % (bits, cost))

	# guess wrong, then initialize gamma and delta, guess a1 = 1
	if SUCCESS==False: 
		gamma, delta = 1,0
		delta += 2*b_1
		gamma += 2
		print_detail('guess wrong! a_1 = 1, b_1 = %d' % b_1)

		# recover other bits of gamma and delta
		for i in range(2,bits):

			#recover a_i
			if (det - gamma^2 + delta^2)%2^(i+2) ==0:
				a_i = 0
			else:
				a_i = 1

			# recover b_i
			b_i = 1 - verification_oracle(E1, (1+2^(b-i-2)*delta)*R1 + 2^(b-i-1)*gamma * S1, (1-2^(b-i-2)*delta)*S1, E2, (1-2^(b-i-2)*delta)*R2 + 2^(b-i-1)*gamma * S2, (1+2^(b-i-2)*delta)*S2)

			gamma += a_i * 2^i
			delta += b_i * 2^i
			print_detail('a_%d = %d, b_%d = %d' % (i,a_i,i,b_i))

		if TorAtk_alternative(gamma, delta):
			end = time.time()
			cost = end - start
			SUCCESS = True
			print_info('Successfully recover %d bits of secret matrix in %.3fs!' % (bits, cost))

elif SUCCESS==False:

	# recover a_1 
	a_1 = verification_oracle(E1, R1, S1 + 2^(b-2) * R1, E2, R2 + 2^(b-2) * S2, S2)

	gamma += 2*a_1

	# guess b1 = 0 and recover other bits of gamma and delta
	print_detail('a_1 = %d, guess b_1 = 0' % a_1)

	for i in range(2,bits):

		#recover b_i
		if (det - gamma^2 + delta^2)%2^(i+2) ==0:
			b_i = 0
		else:
			b_i = 1

		# recover a_i
		a_i = verification_oracle(E1, (1+2^(b-i-2)*gamma)*R1, 2^(b-i-1)*delta * R1 + (1-2^(b-i-2)*gamma)*S1, E2, (1+2^(b-i-2)*gamma)*R2 + 2^(b-i-1)*delta * S2, (1-2^(b-i-2)*gamma)*S2)


		delta += b_i * 2^i
		gamma += a_i * 2^i
		print_detail('a_%d = %d, b_%d = %d' % (i,a_i,i,b_i))

	if TorAtk_alternative(gamma, delta):
		end = time.time()
		cost = end - start
		SUCCESS = True
		print_info('Successfully recover %d bits of secret matrix in %.3fs!' % (bits, cost))

	# guess wrong, then initialize gamma and delta, guess b1 = 1
	if SUCCESS==False:
		gamma, delta = 0,1
		gamma += 2*a_1
		delta += 2
		print_detail('guess wrong! a_1 = %d, b_1 = 1' % a_1)
		
		for i in range(2,bits):

			#recover b_i
			if (det - gamma^2 + delta^2)%2^(i+2) ==0:
				b_i = 0
			else:
				b_i = 1

			# recover a_i
			a_i = verification_oracle(E1, (1+2^(b-i-2)*gamma)*R1, 2^(b-i-1)*delta * R1 + (1-2^(b-i-2)*gamma)*S1, E2, (1+2^(b-i-2)*gamma)*R2 + 2^(b-i-1)*delta * S2, (1-2^(b-i-2)*gamma)*S2)


			delta += b_i * 2^i
			gamma += a_i * 2^i
			print_detail('a_%d = %d, b_%d = %d' % (i,a_i,i,b_i))

		if TorAtk_alternative(gamma, delta):
			end = time.time()
			cost = end - start
			SUCCESS = True
			print_info('Successfully recover %d bits of secret matrix in %.3fs!' % (bits, cost))

if SUCCESS==False:
	print_info('Failure!')
