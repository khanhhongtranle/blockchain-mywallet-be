import hashlib

class Block:
    def __init__(self, index: int, previousHash: str, timestamp: int, data: str, difficulty: int, nonce: int):
        self.hash: str
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.data = data
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = self.calculateHash()

    def calculateHash(self,block=None):
        sha256 = hashlib.sha256()
        if block == None:
            sha256.update(str(self.index) + str(self.previousHash) + str(self.timestamp) + str(self.data))
        else:
            sha256.update(str(block.index) + str(block.previousHash) + str(block.timestamp) + str(block.data))
        return sha256.digest()

    def validateBlock(self, previousBlock):
        if self.index - previousBlock.index != 1:
            return False
        if self.previousHash != previousBlock.hash:
            return False
        if self.calculateHash(block=self) != self.hash:
            return False

    def validateBlockStructure(self):
        return type(self.index) is int and type(self.hash) is str and type(self.previousHash) is str and type(self.timestamp) is int and type(self.data) is str

    def findBlock(self, index: int, previousHash: str, timestamp: int, data: str, difficulty: int):
        nonce = 0
        while (True):
            hash = self.calculateHash()
