import nufhe
import numpy
import pickle
import pandas as pd
from binascii import unhexlify
from sputnik.engine import Sputnik
from sputnik.parser import Parser
from flask import Flask, request
from flask_json import FlaskJSON, JsonError, json_response, as_json
import collections

SIZE = 32
app = Flask(__name__)
FlaskJSON(app)

def flatten(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def bin_array(num, m):
    """Convert a positive integer num into an m-bit bit vector"""
    return numpy.array(list(numpy.binary_repr(num).zfill(m))).astype(numpy.bool)


def list_or_plain(possible_array):
  if possible_array.shape is ():
    return int(str(possible_array)) # num
  else:
    return [list_or_plain(child) for child in possible_array]

def array_to_lists(array):
  return list_or_plain(array)

def serialize(lwe):
  return dict(
    a=array_to_lists(lwe.a),
    b=array_to_lists(lwe.b),
    var=0,#array_to_lists(lwe.current_variances),
    params=dict(
      size=lwe.params.size,
      min=lwe.params.min_noise,
      max=lwe.params.max_noise)
  )

class VM:
  def age_restriction(self, payload):
    print(payload)
    # return payload['birthdate']
    rng = numpy.random.RandomState(42)
    rngB = numpy.random.RandomState(43)
    SputnikParser = Parser('contracts/contract.sputnik')
    proggy = SputnikParser.get_program()
    sputnik = Sputnik(proggy, None)
    secret_key, bootstrap_key = nufhe.make_key_pair(sputnik.thr, rng, transform_type='NTT')
    secret_key_b, bootstrap_key_b = nufhe.make_key_pair(sputnik.thr, rngB, transform_type='NTT')

    plain = bin_array(payload['birthdate'], SIZE)
    mask16 = bin_array(payload['constraits'][0], SIZE)
    mask32 = bin_array(payload['constraits'][1], SIZE)
    mask64 = bin_array(payload['constraits'][2], SIZE)
    mask128 = bin_array(payload['constraits'][3], SIZE)
    expected = bin_array(0, SIZE)

    enc_expected = nufhe.encrypt(sputnik.thr, rng, secret_key, expected)
    enc_mask16 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask16)
    enc_mask32 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask32)
    enc_mask64 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask64)
    enc_mask128 = nufhe.encrypt(sputnik.thr, rng, secret_key, mask128)
    enc_plain = nufhe.encrypt(sputnik.thr, rng, secret_key, plain)


    contract_state_out, merkle_tree = sputnik.execute_program(
      plain=enc_plain, 
      mask16=enc_mask16, 
      mask32=enc_mask32, 
      mask64=enc_mask64, 
      mask128=enc_mask128, 
      test_key=bootstrap_key)

    dec_out = nufhe.decrypt(sputnik.thr, secret_key, contract_state_out)
    dec_trash = nufhe.decrypt(sputnik.thr, secret_key_b, contract_state_out)
    enc_trash = nufhe.encrypt(sputnik.thr, secret_key_b, dec_trash)
    dec_trash_to_orginal = nufhe.decrypt(sputnik.thr, secret_key, enc_trash)

    print(dec_trash)
    out = False 
    for i in range(dec_out.shape[0]):
      if dec_out[i] is plain[i]:
        out = True
        break

    print(dec_out)
    return dict(out=out)

  def encrypt(self, data, base):
    rng = numpy.random.RandomState(42)
    SputnikParser = Parser('contracts/contract.sputnik')
    proggy = SputnikParser.get_program()
    sputnik = Sputnik(proggy, None)
    secret_key, bootstrap_key = nufhe.make_key_pair(sputnik.thr, rng, transform_type='NTT')

    result = dict()
    flat = flatten(data)

    for key, value in flat.items():
      if isinstance(value, (int, float)):
        # result[key] = value
        result[key] = serialize(nufhe.encrypt(sputnik.thr, rng, secret_key, bin_array(value, SIZE)))


    # print(result['country'])
    # for key, value in flatten(result).items():
    #   print(f'type of {key} is {type(value)}')

    
      
    return result
    # print(dir(result['country'].a.data))
    # return(dict(a=result['country'].a.tolist(), 
    # b=result['country'].b.tolist(), 
    # variances=result['country'].current_variances.tolist(), 
    # params=result['country'].params.tolist()))

vm = VM()

@app.route('/execute/<string:contract>', methods=['POST'])
def execute(contract):
  payload = request.get_json(force=True)
  VM_func = getattr(vm, contract)
  return json_response(contract=contract, test=VM_func(payload))

@app.route('/encrypt', methods=['POST'])
def encrypt():
  payload = request.get_json(force=True)
  return json_response(data=vm.encrypt(payload, 1))


if __name__ == '__main__':
    app.run()