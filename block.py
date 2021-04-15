import hashlib

class Block:
    def __init__(self, index, previousHash, timestamp, data):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.data = data
        self.hash = self.calculateHash()

    def calculateHash(self):
        sha256 = hashlib.sha256()
        sha256.update(str(self.index) + str(self.previousHash) + str(self.timestamp) + str(self.data))
        return self.hash


