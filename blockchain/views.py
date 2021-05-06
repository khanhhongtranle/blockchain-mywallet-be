from django.http import HttpResponse

import base64
import time
import uuid

from .blockchain import Block, InputTransaction, OutputTransaction, Transaction, BlockChain
import json, pymongo, os, hashlib, ecdsa, jwt, requests

salt = os.urandom(32)  # Salt for hash password to write into db

client = pymongo.MongoClient("localhost", 27017)
db = client.myDatabase


# Hash password
def hash_password(password, salt):
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
        'password': hash_password(password=password, salt=salt),
        'private_key': private_key,
        'public_key': public_key,
        'salt': salt
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

# Access to wallet
def access_my_wallet(req):
    request_data = json.loads(req.body.decode('utf-8'))
    req_password = str(request_data['password'])
    req_private_key = str(request_data['private_key'])
    hashed_password = hash_password(password=req_password, salt=salt)
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
        return HttpResponse(json.dumps(response_body), status=201)
    else:
        response_body = {
            'message': 'Failed',
            'data': {

            }
        }
        return HttpResponse(json.dumps(response_body), status=200)


# Create new wallet
# @app.route('/create_new_wallet', methods=['POST'])
def create_new_wallet(req):
    request_data = json.loads(req.body.decode('utf-8'))
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
    return HttpResponse(json.dumps(response_body), status=201)


# Block chain
blockchain = BlockChain()

# Chứa địa chỉ host của các thành viên tham gia khác của mạng
peers = set()


# @app.route('/register_new_node', methods=['POST'])
def register_new_peer(req):
    node_address = req.POST['node_address']
    if not node_address:
        return HttpResponse("Invalid data", status=400)

    peers.add(node_address)

    return get_chain()


# @app.route('/register_existing_node', methods=['POST'])
def register_with_exixting_node(req):
    node_address = req.POST
    if not node_address:
        return HttpResponse("Invalid data", status=400)

    data = {
        "node_address": '127.0.0.1'  # tam thoi
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(node_address + "/register_new_node", data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return HttpResponse("Registration successful", status=201)
    else:
        return HttpResponse(response.content, status=response.status_code)


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


# @app.route('/chains', methods=['GET'])
def get_chain(req):
    headers = req.headers
    if check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return HttpResponse(json.dumps({
        'length': len(chain_data),
        'chain': chain_data
    }))


# @app.route('/new_transaction', methods=['POST'])
def new_transaction(req):
    headers = req.headers
    if check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)

    data = req.GET
    required_fields = ['in', 'out']

    for field in required_fields:
        if not data.get(field):
            return HttpResponse("Invalid transaction data", status=404)

    # data['timestamp'] = time.time()

    blockchain.add_new_transaction(data)

    return HttpResponse("Success", status=201)


# @app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions(req):
    result = blockchain.mine()
    if not result:
        return HttpResponse("No transaction to mine")
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(block=blockchain.last_block)
    return HttpResponse("Block #{} is mined".format(result))


# @app.route('/pending_tx')
def get_pending_tx(req):
    return HttpResponse(json.dumps(blockchain.unconfirmed_transactions))


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


# add block not passed add to unconfirmed transaction step
# @app.route('/add_block', methods=['POST'])
def verify_and_add_block(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        print('You do not have access')
        return HttpResponse("You do not have access", status=404)

    transaction_data = json.loads(req.body.decode('utf-8'))
    required_fields = ['in', 'out']

    for field in required_fields:
        if not transaction_data.get(field):
            print('Invalid transaction data')
            return HttpResponse("Invalid transaction data", status=404)

    the_last_block = blockchain.last_block
    transactions = []
    in_transaction = InputTransaction(receiver_address=transaction_data['in']['receiver_address'], sender_address=transaction_data['in']['sender_address'], amount=transaction_data['in']['amount'])
    out_transaction = OutputTransaction(sender_address=transaction_data['out']['sender_address'], receiver_address=transaction_data['out']['receiver_address'], amount=transaction_data['out']['amount'])
    transaction = Transaction(id=uuid.uuid4(), input_transaction=in_transaction, output_transaction=out_transaction)
    transactions.append(transaction)
    block = Block(index=the_last_block.index + 1, transactions=transactions, timestamp=time.time(), previous_hash=the_last_block.hash)
    proof = blockchain.proof_of_work(block)
    added = blockchain.add_block_to_blockchain(block=block, proof=proof)
    if not added:
        print('The block was discarded by the node')
        return HttpResponse("The block was discarded by the node", status=404)

    return HttpResponse("The block added to the chain", status=201)


def announce_new_block(block):
    for node in peers:
        url = "{}add_block".format(peers)
        requests.post(url, data=json.dumps(block.__dict__, sort_keys=True))
