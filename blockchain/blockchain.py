import time
from hashlib import sha256
import uuid


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
    def __init__(self, id, input_transaction: InputTransaction, output_transaction: OutputTransaction):
        self.id = id
        self.input_transaction = input_transaction
        self.output_transaction = output_transaction

    def get_transaction_id(self):
        return self.id

    def get_in_transaction(self):
        return self.input_transaction

    def get_out_transaction(self):
        return self.output_transaction


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()
        self.nonce = 0

    def compute_hash(self):
        string = (str(self.index) + str(self.previous_hash) + str(self.timestamp) + str(self.transactions)).encode('utf-8')
        sha256().update(string)
        return sha256().hexdigest()

    def is_valid_proof(self, block_hash, difficulty):
        result = False
        if block_hash == self.compute_hash() and block_hash.startswith('0' * difficulty):
            result = True
        return result


class BlockChain:
    difficulty = 2

    def __init__(self):
        self.__chain = []  # keeps all blocks
        self.unconfirmed_transactions = []  # keeps all unconfirmned transactions
        self.__create_genesis_block()

    @property
    def chain(self):
        return self.__chain

    @chain.setter
    def chain(self, new_chain):
        self.__chain = new_chain

    @chain.getter
    def chain(self):
        return self.__chain

    def __create_genesis_block(self):
        genesis_block = Block(index=0, transactions=[], timestamp=time.time(), previous_hash="0")
        self.__append_to_chain(genesis_block)

    def __append_to_chain(self, new_block):
        self.__chain.append(new_block)

    @property
    def last_block(self):
        return self.__chain[-1]

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

        if not block.is_valid_proof(block_hash=block.hash, difficulty=self.difficulty):
            return False

        block.hash = proof

        self.__append_to_chain(block)
        return True

    def add_new_transaction(self, transaction_dumps):
        in_transaction = InputTransaction(receiver_address=transaction_dumps['in']['receiver_address'], sender_address=transaction_dumps['in']['sender_address'], amount=transaction_dumps['in']['amount'])
        out_transaction = OutputTransaction(sender_address=transaction_dumps['out']['sender_address'], receiver_address=transaction_dumps['out']['receiver_address'], amount=transaction_dumps['out']['amount'])
        transaction = Transaction(id=uuid.uuid4(), input_transaction=in_transaction, output_transaction=out_transaction)
        self.unconfirmed_transactions.append(transaction)

    def mine(self):
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1, transactions=self.unconfirmed_transactions, timestamp=time.time(), previous_hash=last_block.hash)

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
