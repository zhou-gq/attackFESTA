"""
To record the running time of two exceptions in FESTA with 128-bit security on your machine

```
sage exception_time.py
```

The running time of higher security can be recorded with

```
sage exception_time.py [--128, --192, --256]
```

If you want to repeated n times, run the file with 'n' flag. For example:

```
sage exception_time.py 10
```
"""


from sage.all_cmdline import *   # import sage library
import time
from festa import FESTA
from parameters.params import parameter_sets
from utilities.pairing import weil_pairing_pari
from utilities.discrete_log import windowed_pohlig_hellman
from utilities.utils import print_info, print_detail

# This is a function that records average running time of exceptions in personal computer,
# which will be called in 'attack_festa.sage' if specifying parameter '--basetime'. It 
# returns the intermediate running time of exception 1 and exception 2.
def average_time(alice, bob, b, E1, R1, S1, E2, R2, S2):
	print_info('Record running time of exceptions:')
	t1,t2=0,0
	for _ in range(3):
		try:
			# if b_0 = 0, then there is no ValueError.
			cpiher_prime = (E1, R1 + 2**(b-1) * S1, S1, E2, R2 , S2 + 2**(b-1) * R2)
			c_prime = bob.compress_ciphertext(cpiher_prime)
			start = time.time()
			m2=alice.decrypt(c_prime)
		except ValueError:
			pass
		end = time.time()
		t2 += (end - start)

		try:
			# if b_0 = 1, then there is no ValueError.
			cpiher_prime = (E1, R1 + 2**(b-1) * S1, S1, E2, R2 + 2**(b-1) * S2, S2)
			c_prime = bob.compress_ciphertext(cpiher_prime)
			start = time.time()
			m2=alice.decrypt(c_prime)
		except ValueError:
			pass
		end = time.time()
		t1 += end - start

	t1/=3
	t2/=3
	if t1>t2:
		t1,t2 = t2, t1
	print_detail('exception 1: %.3fs,  exception 2: %.3fs.' % (t1,t2))
	return (t1+t2)/2

# This source file records exceptions repeaded several times. It prints the running time of
# each exception.
if __name__ == '__main__':

	SECURITY = "128"
	times = 5
	for arg in sys.argv[1:]:
	    if arg.lower() in ["--192", "-II"]:
	        SECURITY = "192"
	    elif arg.lower() in ["--256", "-V"]:
	        SECURITY = "256"
	    elif arg.isnumeric() and int(arg) > 0:
	    	times = int(arg)

	NAME = "FESTA_" + SECURITY

	# Initialize Alice and Bob, where secret matrices are circulant.
	params = parameter_sets[NAME]
	alice = FESTA(params, diag=False)
	bob   = FESTA(params, diag=False)

	# Keygen
	alice.keygen()
	print_info('Keygen successfully!')

	# Encryption
	pk = alice.export_public_key()
	m = randint(0, 2**alice.lambda_security - 1)
	c = bob.encrypt(pk, m)
	print_info('Encrypt successfully!')

	# Record exception time

	b = alice.b
	ct = alice.decompress_ciphertext(c)
	E1, R1, S1, E2, R2, S2 = ct

	print_info('Running time of exceptions in ' + NAME + ':')

	# Extract the first bit b_0 of delta
	b_0 = alice.sk[0][0][1]%2

	T1, T2 = 0, 0
		
	for _ in range(times):
		try:
			# If b_0 = 0, then there is a 'ValueError' corresponding to exception 1.
			ct_prime = (E1, R1 + 2**(b-1) * S1, S1, E2, R2 , S2 + 2**(b-1) * R2)
			c_prime = bob.compress_ciphertext(ct_prime)
			start = time.time()
			m2=alice.decrypt(c_prime)
		except ValueError:
			pass
		end = time.time()
		t1 = end - start

		try:
			# if b_0 = 0, then there is no ValueError corresponding to exception 2.
			ct_prime = (E1, R1 + 2**(b-1) * S1, S1, E2, R2 + 2**(b-1) * S2, S2)
			c_prime = bob.compress_ciphertext(ct_prime)
			start = time.time()
			m2=alice.decrypt(c_prime)
		except ValueError:
			pass
		end = time.time()
		t2 = end - start

		# t1 always represents the time of exception 1, and t2 always represents the time of exception 2.
		if b_0 ==1:
			t1, t2 = t2, t1			
		T1 += t1
		T2 += t2	

		print_detail('exception 1: %.3fs,  exception 2: %.3fs.' % (t1,t2))

	print_info('Average time of exception 1: %.3fs,  average time of exception 2: %.3fs.' % (T1/times,T2/times))