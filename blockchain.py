from block import Block
from time import time

class BlockChain:
    def __init__(self):
        self.__chains = []
        self.__transactions = []
        self.__chains.append(self.genesisBlock())
        pass

    def genesisBlock(self):
        return Block(index=0, previousHash="", timestamp=time(), data="first block")

    def generateNextBlock(self, data):
        previousBlock = self.getLatestBlock()
        nextIndex = previousBlock.index + 1
        nextTimestamp = time()


    def getLatestBlock(self):
        return self.__chains[len(self.__chains) - 1]
