import base64
import time
from new import Block
from new import BlockChain
from flask import Flask, request
import requests
import json
from flask_pymongo import PyMongo
import os
import hashlib
import ecdsa
import jwt

salt = os.urandom(32)  # Salt for hash password to write into db

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
mongo = PyMongo(app)
db = mongo.db


# Hash password
def hash_password(password):
    # Hash password
    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )
    return key.hex()


# Generate private key & public key by ECDSA key
def generate_ecdsa_key():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  # this is your sign (private key)
    private_key = sk.to_string().hex()  # convert your private key to hex
    vk = sk.get_verifying_key()  # this is your verification key (public key)
    public_key = vk.to_string().hex()
    # we are going to encode the public key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key)).hex()

    return {
        'private_key': private_key,
        'public_key': public_key
    }


# Database MongoDb
def write_wallet_into_db(password, private_key, public_key):
    db.wallet.insert_one({
        'password': hash_password(password=password),
        'private_key': private_key,
        'public_key': public_key
    })


# Check jwt token
def check_jwt_token(headers):
    jwt_header = headers.get('Authorization')
    jwt_token = jwt_header.replace('JWT ', '')
    decode = jwt.decode(jwt_token, 'secret', algorithms=['HS256'])
    private_key = decode['private_key']
    public_key = decode['public_key']
    found_wallet_data = db.wallet.find_one({'$and': [{'private_key': private_key}, {'public_key': public_key}]})
    if found_wallet_data:
        return True
    return False

# test jwt token
@app.route('/test', methods=['GET'])
def test():
    headers=request.headers
    print(check_jwt_token(headers=headers))
    return "ok", 201


# Access to wallet
@app.route('/access_my_wallet', methods=['POST'])
def access_my_wallet():
    request_data = request.get_json(force=True)
    req_password = request_data['password']
    req_private_key = request_data['private_key']
    hashed_password = hash_password(password=req_password)
    found_wallet_data = db.wallet.find_one({'$and': [{'private_key': req_private_key}, {'password': hashed_password}]})
    if found_wallet_data:
        # Create jwt token by HS256
        encode_token = jwt.encode({
            'public_key': found_wallet_data['public_key'],
            'private_key': found_wallet_data['private_key']
        },
            'secret',
            algorithm='HS256')
        response_body = {
            'message': 'Success',
            'data': {
                'public_key': found_wallet_data['public_key'],
                'jwt_token': encode_token
            }
        }
        return json.dumps(response_body), 201
    else:
        response_body = {
            'message': 'Failed',
            'data': {

            }
        }
        return json.dumps(response_body), 400


# Create new wallet
@app.route('/create_new_wallet', methods=['POST'])
def create_new_wallet():
    request_data = request.get_json(force=True)
    req_password = request_data['password']
    # Generate private & public key
    rsa_key = generate_ecdsa_key()
    private_key = rsa_key['private_key']
    public_key = rsa_key['public_key']
    # Save to db
    write_wallet_into_db(password=req_password, private_key=private_key, public_key=public_key)
    response_body = {
        'message': 'Success',
        'data': {
            'private_key': private_key
        }
    }
    return json.dumps(response_body), 201


# Block chain
blockchain = BlockChain()

# Chứa địa chỉ host của các thành viên tham gia khác của mạng
peers = set()


@app.after_request
def apply_caching(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route('/register_new_node', methods=['POST'])
def register_new_peer():
    node_address = request.get_json(force=True)['node_address']
    if not node_address:
        return "Invalid data", 400

    peers.add(node_address)

    return get_chain()


@app.route('/register_existing_node', methods=['POST'])
def register_with_exixting_node():
    node_address = request.get_json(force=True)
    if not node_address:
        return "Invalid data", 400

    data = {
        "node_address": request.host_url
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(node_address + "/register_node", data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        return response.content, response.status_code


def create_chain_from_dump(chain_dump):
    new_blockchain = BlockChain()
    for index, block_data in enumerate(chain_dump):
        new_block = Block(index=block_data['index'], transactions=block_data['transactions'], timestamp=block_data['timestamp'], previous_hash=block_data['previous_hash'])
        proof = block_data['hash']
        if index > 0:
            added_to_blockchain_result = blockchain.add_block_to_blockchain(block=new_block, proof=proof)
            if not added_to_blockchain_result:
                return Exception("The chain dump os sdnaskdhas")
        else:
            new_blockchain.chain = new_blockchain.chain.append(new_block)
        return new_blockchain


@app.route('/chains', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({
        'length': len(chain_data),
        'chain': chain_data
    })


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    data = request.get_json(force=True)
    required_fields = ['author', 'content']

    for field in required_fields:
        if not data.get(field):
            return "Invalid transaction data", 404

    data['timestamp'] = time.time()

    blockchain.add_new_transaction(data)

    return "Success", 201


@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "No transaction to mine"
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(block=blockchain.last_block)
    return "Block #{} is mined".format(result)


@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
    global blockchain
    longest_chain = None
    current_len = len(blockchain.chain)
    for node in peers:
        response = requests.get('{}/chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain=chain):
            current_len = length
            longest_chain = chain

        if longest_chain:
            blockchain = longest_chain
            return True

    return False


@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json(force=True)
    block = Block(index=block_data['index'], transactions=block_data['transactions'], timestamp=block_data['timestamp'], previous_hash=block_data['previous_hash'])
    proof = block_data['hash']
    added = blockchain.add_block_to_blockchain(block=block, proof=proof)
    if not added:
        return "The block was discarded by the node", 400

    return "The block added to the chain", 201


def announce_new_block(block):
    for node in peers:
        url = "{}add_block".format(peers)
        requests.post(url, data=json.dumps(block.__dict__, sort_keys=True))
