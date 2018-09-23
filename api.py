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
    SputnikParser = Parser('contracts/contract.sputnik')
    proggy = SputnikParser.get_program()
    sputnik = Sputnik(proggy, None)

    enc_mask16 = bin_array(payload.constraits[0], SIZE)
    enc_mask32 = bin_array(payload.constraits[1], SIZE)
    enc_mask64 = bin_array(payload.constraits[2], SIZE)
    enc_mask128 = bin_array(payload.constraits[3], SIZE)

    contract_state_out, merkle_tree = sputnik.execute_program(
      plain=enc_plain, 
      mask16=enc_mask16, 
      mask32=enc_mask32, 
      mask64=enc_mask64, 
      mask128=enc_mask128, 
      test_key=bootstrap_key)

    return dict(out=contract_state_out, tree=merkle_tree)

  def encrypt(self, data, base):
    SputnikParser = Parser('contracts/contract.sputnik')
    proggy = SputnikParser.get_program()
    sputnik = Sputnik(proggy, None)
    rng = numpy.random.RandomState(42)
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