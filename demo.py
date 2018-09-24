#1
import nufhe
import numpy
import pickle
from binascii import unhexlify
from sputnik.engine import Sputnik
from sputnik.parser import Parser
from vyper import compiler


def bin_array(num, m):
    """Convert a positive integer num into an m-bit bit vector"""
    return numpy.array(list(numpy.binary_repr(num).zfill(m))).astype(numpy.bool)

if __name__ == '__main__1':
    plain = bin_array(24, 32)
    pad = bin_array(16, 32)
    reference = plain & pad
    print(plain)
    print(pad)

    # print(numpy.array([True] * 32).astype(numpy.bool) == True)
    print(numpy.array(reference) == numpy.array([True] * 32).astype(numpy.bool))


def pair(op, boot, enc_left):
    SputnikParser = Parser(f'contracts/{op}.sputnik')
    contract_state_out, merkle_tree = sputnik.execute_program(left=enc_left, test_key=boot)

    return (contract_state_out, merkle_tree)


def pair(op, boot, enc_left, enc_right):
    SputnikParser = Parser(f'contracts/{op}.sputnik')
    contract_state_out, merkle_tree = sputnik.execute_program(left=enc_left, right=enc_right, test_key=boot)

    return (contract_state_out, merkle_tree)

    

def calc(age):
    #2
    # Setup Sputnik and deploy vyper contract
    SputnikParser = Parser('contracts/contract.sputnik')
    proggy = SputnikParser.get_program()
    sputnik = Sputnik(proggy, None)

    with open('contracts/hasheater.vy', 'r') as f:
        contract_code = f.read()

    #3
    # Setup numpy (insecure, but it's a hackathon...)
    rng = numpy.random.RandomState()

    #4
    # Setup NuFHE
    secret_key, bootstrap_key = nufhe.make_key_pair(sputnik.thr, rng, transform_type='NTT')
    size = 32

    #5
    # Setup our plaintext and pad, then encrypt them
    mask16 = bin_array(16, 32)
    mask32 = bin_array(32, 32)
    mask64 = bin_array(64, 32)
    mask128 = bin_array(128, 32)

    enc_mask16 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask16)
    enc_mask32 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask32)
    enc_mask64 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask64)
    enc_mask128 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask128)

    enc_plain = nufhe.encrypt(sputnik.thr, rng, secret_key, bin_array(age, 32))
    # Execute the homomorphic contract
    contract_state_out, merkle_tree = sputnik.execute_program(plain=enc_plain, mask16=enc_mask16, mask32=enc_mask32, mask64=enc_mask64, mask128=enc_mask128, test_key=bootstrap_key)

    #7 Show the reference vs the homomorphic contract output

    # reference = plain + ~pad
    dec_fhe_ref = nufhe.decrypt(sputnik.thr, secret_key, contract_state_out)

    allow = True
    for bit in dec_fhe_ref:
        if bit:
            allow = False
            break

    print(f"Refect at {age}? {allow}")
    print(dec_fhe_ref)


calc(15)
calc(17)
calc(18)
calc(25)
calc(60)
calc(83)
calc(3)