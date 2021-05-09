from django.http import HttpResponse
import bcrypt
import base64
import time
import uuid
import socketio
from .blockchain import Block, InputTransaction, OutputTransaction, Transaction, BlockChain
import json, pymongo, os, hashlib, ecdsa, jwt, requests

salt = os.urandom(32)  # Salt for hash password to write into db

client = pymongo.MongoClient("localhost", 27017)
db = client.myDatabase

# Socker IO
sio = socketio.Server(cors_allowed_origins='*')
app = socketio.WSGIApp(sio)


@sio.event
async def client_connect(sid, data):
    sio.emit('sever.connect', 'Connected.')


# has a new block added to block chain
def socket_emit_blockchain_has_changed(block, transactions_arr):
    lastest_block = {
        'index': block.index,
        'timestamp': block.timestamp,
        'miner': block.miner,
        'num_of_tx': len(block.transactions),
    }

    lastest_transactions = []
    for tx_index in range(len(transactions_arr)):
        tx = transactions_arr[tx_index]
        a_transaction = {
            'sender_address': tx.get_out_transaction().get_sender_address(),
            'receiver_address': tx.get_out_transaction().get_receiver_address(),
            'amount': tx.get_out_transaction().get_amount(),
            'id': str(tx.get_transaction_id()),
            'timestamp': tx.get_timestamp(),
            'confirmed_timestamp': tx.get_confirmed_timestamp()
        }
        lastest_transactions.append(a_transaction)

    sio.emit('blockchain.update', json.dumps({'lastest_block': lastest_block, 'lastest_transactions': lastest_transactions}))


def socket_emit_bought_coin(amount, address):
    sio.emit('amount.update', {'amount': amount, 'address': address})


# new transaction that is unconfimed transaction
def socket_emit_new_transaction(new_tx):
    sio.emit('transaction.update', new_tx)


# Hash password
def hash_password(password):
    # Hash password
    # key = hashlib.pbkdf2_hmac(
    #     'sha256',  # The hash digest algorithm for HMAC
    #     password.encode('utf-8'),  # Convert the password to bytes
    #     salt,  # Provide the salt
    #     100000  # It is recommended to use at least 100,000 iterations of SHA-256
    # )
    # key = hash(password+salt)
    password = password.encode()
    key = bcrypt.hashpw(password=password, salt=bcrypt.gensalt())
    return key


def check_password(password_plain_text, hashed_password):
    password_plain_text = password_plain_text.encode()
    return bcrypt.checkpw(password=password_plain_text, hashed_password=hashed_password)


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
        'public_key': public_key,
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
    found_wallet_by_private_key = db.wallet.find_one({'private_key': req_private_key})
    hashed_password = hash_password(password=req_password)
    if found_wallet_by_private_key and check_password(password_plain_text=req_password, hashed_password=hashed_password):
        # Create jwt token by HS256
        encode_token = jwt.encode({
            'public_key': found_wallet_by_private_key['public_key'],
            'private_key': found_wallet_by_private_key['private_key']
        },
            'secret',
            algorithm='HS256')
        response_body = {
            'message': 'Success',
            'data': {
                'public_key': found_wallet_by_private_key['public_key'],
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
    if not check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)
    chain_data = []
    for block in blockchain.chain:
        element = {
            'index': block.index,
            'timestamp': block.timestamp,
            'miner': block.miner,
            'num_of_tx': len(block.transactions),
        }
        chain_data.append(element)
    return HttpResponse(json.dumps(chain_data), 200)


# @app.route('/new_transaction', methods=['POST'])
def new_transaction(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)

    data = json.loads(req.body.decode('utf-8'))
    required_fields = ['in', 'out']

    for field in required_fields:
        if not data.get(field):
            return HttpResponse("Invalid transaction data", status=404)

    # Check unspent amount
    unspent_amount = blockchain.get_amount(data['out']['sender_address'])
    needed_amount = data['out']['amount']
    if needed_amount > unspent_amount:
        response_body = {
            'message': 'Not enough coins to send this transaction',
            'data': {
                'unspent_amount': unspent_amount,
                'needed_amount': needed_amount
            }
        }
        return HttpResponse(json.dumps(response_body), status=200)

    blockchain.add_new_transaction(data)

    newest_tx = blockchain.last_unconfirmed_tx
    newest_tx_data = {
        'sender_address': newest_tx.get_out_transaction().get_sender_address(),
        'receiver_address': newest_tx.get_out_transaction().get_receiver_address(),
        'amount': newest_tx.get_out_transaction().get_amount(),
        'id': newest_tx.get_transaction_id(),
        'timestamp': newest_tx.get_timestamp()
    }
    socket_emit_new_transaction(new_tx=newest_tx_data)

    return HttpResponse("Success", status=201)


# @app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)

    data = json.loads(req.body.decode('utf-8'))

    unconfirmed_tx = blockchain.unconfirmed_transactions

    result = blockchain.mine(data['miner'])
    if not result:
        return HttpResponse("No transaction to mine")
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(block=blockchain.last_block)

    socket_emit_blockchain_has_changed(block=blockchain.last_block, transactions_arr=unconfirmed_tx)
    return HttpResponse("Block #{} is mined".format(result))


# @app.route('/pending_tx')
def get_pending_tx(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)

    result = []
    # result = {
    #       {
    #           sender_address: ,
    #           receiver_address: ,
    #           amount: ,
    #       }
    # }
    for index in range(len(blockchain.unconfirmed_transactions)):
        tx = blockchain.unconfirmed_transactions[index]
        tx_out = tx.get_out_transaction()
        element = {
            'sender_address': tx_out.get_sender_address(),
            'receiver_address': tx_out.get_receiver_address(),
            'amount': tx_out.get_amount(),
            'id': tx.get_id(),
            'timestamp': tx.get_timestamp()
        }
        result.append(element)

    return HttpResponse(json.dumps(result), 200)


def get_confirmed_tx(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        return HttpResponse("You do not have access", status=404)

    result = []
    # result = {
    #       {
    #           sender_address: ,
    #           receiver_address: ,
    #           amount: ,
    #       }
    # }
    for index in range(len(blockchain.chain)):
        block = blockchain.chain[index]
        for tx_index in range(len(block.transactions)):
            tx = block.transactions[tx_index]
            tx_out = tx.get_out_transaction()
            element = {
                'sender_address': tx_out.get_sender_address(),
                'receiver_address': tx_out.get_receiver_address(),
                'amount': tx_out.get_amount(),
                'id': str(tx.get_id()),
                'timestamp': tx.get_timestamp(),
                'confirmed_timestamp': tx.get_confirmed_timestamp()
            }
            result.append(element)

    return HttpResponse(json.dumps(result), 200)


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
    transaction = Transaction(id=uuid.uuid4(), input_transaction=in_transaction, output_transaction=out_transaction, timestamp=time.time())
    transactions.append(transaction)
    block = Block(index=the_last_block.index + 1, transactions=transactions, timestamp=time.time(), previous_hash=the_last_block.hash, miner='TLKH')
    proof = blockchain.proof_of_work(block)
    added = blockchain.add_block_to_blockchain(block=block, proof=proof)
    if not added:
        print('The block was discarded by the node')
        return HttpResponse("The block was discarded by the node", status=200)

    socket_emit_bought_coin(transaction_data['in']['amount'], transaction_data['in']['receiver_address'])
    socket_emit_blockchain_has_changed(block=blockchain.last_block, transactions_arr=transactions)
    return HttpResponse("The block added to the chain", status=201)


def announce_new_block(block):
    for node in peers:
        url = "{}add_block".format(peers)
        requests.post(url, data=json.dumps(block.__dict__, sort_keys=True))


def get_amount(req):
    headers = req.headers
    if not check_jwt_token(headers=headers):
        print('You do not have access')
        return HttpResponse("You do not have access", status=404)

    req_data = json.loads(req.body.decode('utf-8'))
    req_address = req_data['address']
    amount = blockchain.get_amount(req_address)

    response_body = {
        'message': 'Success',
        'data': {
            'amount': amount
        }
    }
    return HttpResponse(json.dumps(response_body), status=201)
