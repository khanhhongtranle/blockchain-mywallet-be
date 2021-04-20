import time

from new import Block
from new import BlockChain
from flask import Flask, request
import requests
import json

app = Flask(__name__)

blockchain = BlockChain()

# Chứa địa chỉ host của các thành viên tham gia khác của mạng
peers = set()

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
        return  "Invalid data", 400

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
    return "Block #{} is mined".format(result)


@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)
