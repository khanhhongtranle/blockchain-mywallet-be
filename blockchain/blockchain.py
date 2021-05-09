import time
from hashlib import sha256
import uuid
import json

class InputTransaction:
    def __init__(self, receiver_address, sender_address, amount):
        self.receiver_address = receiver_address
        self.sender_address = sender_address
        self.amount = amount

    def get_sender_address(self):
        return self.sender_address

    def get_receiver_address(self):
        return self.receiver_address

    def get_amount(self):
        return self.amount


class OutputTransaction:
    def __init__(self, sender_address, receiver_address, amount):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.amount = amount

    def get_sender_address(self):
        return self.sender_address

    def get_receiver_address(self):
        return self.receiver_address

    def get_amount(self):
        return self.amount


class Transaction:
    def __init__(self, id, input_transaction: InputTransaction, output_transaction: OutputTransaction, timestamp):
        self.confirmed_timestamp = None
        self.id = id
        self.input_transaction = input_transaction
        self.output_transaction = output_transaction
        self.timestamp = timestamp

    def get_transaction_id(self):
        return self.id

    def get_in_transaction(self):
        return self.input_transaction

    def get_out_transaction(self):
        return self.output_transaction

    def get_id(self):
        return self.id

    def get_timestamp(self):
        return self.timestamp

    def set_confirmed_timestamp(self, value):
        self.confirmed_timestamp = value

    def get_confirmed_timestamp(self):
        return self.confirmed_timestamp

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,sort_keys=True, indent=4)

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, miner):
        self.nonce = 0
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()
        self.miner = miner

    def compute_hash(self):
        block_string = json.dumps(str(self.nonce)+str(self.index)+str(self.transactions)+str(self.timestamp)+str(self.previous_hash), sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    def is_valid_proof(self, block_hash, difficulty):
        result = False
        if block_hash == self.compute_hash() and block_hash.startswith('0' * difficulty):
            result = True
        return result


class BlockChain:
    difficulty = 1

    def __init__(self):
        self.chain = []  # keeps all blocks
        self.unconfirmed_transactions = []  # keeps all unconfirmned transactions
        self.__create_genesis_block()

    def __create_genesis_block(self):
        genesis_block = Block(index=0, transactions=[], timestamp=time.time(), previous_hash="0", miner=None)
        self.__append_to_chain(genesis_block)

    def __append_to_chain(self, new_block):
        self.chain.append(new_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_block_to_blockchain(self, block, proof):
        previous_hash = self.last_block.hash

        if block.previous_hash != previous_hash:
            return False

        if not block.is_valid_proof(block_hash=proof, difficulty=self.difficulty):
            return False

        block.hash = proof

        # set confirmed time for transactions
        for tx_index in range(len(block.transactions)):
            tx = block.transactions[tx_index]
            tx.set_confirmed_timestamp(time.time())

        self.__append_to_chain(block)
        return True

    def add_new_transaction(self, transaction_dumps):
        in_transaction = InputTransaction(receiver_address=transaction_dumps['in']['receiver_address'], sender_address=transaction_dumps['in']['sender_address'], amount=transaction_dumps['in']['amount'])
        out_transaction = OutputTransaction(sender_address=transaction_dumps['out']['sender_address'], receiver_address=transaction_dumps['out']['receiver_address'], amount=transaction_dumps['out']['amount'])
        id_value = uuid.uuid4()
        transaction = Transaction(id=str(id_value), input_transaction=in_transaction, output_transaction=out_transaction, timestamp=time.time())
        self.unconfirmed_transactions.append(transaction)

    def mine(self, miner):
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1, transactions=self.unconfirmed_transactions, timestamp=time.time(), previous_hash=last_block.hash, miner=miner)

        proof = self.proof_of_work(new_block)

        if self.add_block_to_blockchain(block=new_block, proof=proof):
            self.unconfirmed_transactions = []
            return new_block.index

        return -1  # mining false

    def check_chain_validity(self, chain):
        result = True
        previous_hash = "0"
        for block in chain:
            block_hash = block.hash
            delattr(block, "hash")
            if not block.is_valid_proof(block_hash=block_hash, difficulty=self.difficulty) or previous_hash != block.previous_hash:
                result = False
                break

            block.hash = block_hash
            previous_hash = block_hash

        return result

    def get_amount(self, address):
        amount = 0
        for block_index in range(len(self.chain)):
            block = self.chain[block_index]
            for transaction_index in range(len(block.transactions)):
                transaction = block.transactions[transaction_index]
                if transaction.input_transaction.get_receiver_address() == address:
                    amount += transaction.input_transaction.get_amount()
                if transaction.output_transaction.get_sender_address() == address:
                    amount -= transaction.output_transaction.get_amount()
        return amount

    @property
    def last_unconfirmed_tx(self):
        return self.unconfirmed_transactions[-1]
