from block import Block
from time import time


class BlockChain:
    def __init__(self):
        self.__chains = []
        self.__transactions = []
        firstBlock = self.genesisBlock()
        self.addBlockToChains(firstBlock)
        pass

    def addBlockToChains(self, newBlock):
        self.__chains.append(newBlock)

    def getLatestBlock(self):
        return self.__chains[len(self.__chains) - 1]

    def genesisBlock(self):
        return Block(index=0, previousHash="", timestamp=int(time()), data="first block")

    def generateNextBlock(self, data):
        previousBlock = self.getLatestBlock()
        nextIndex = previousBlock.index + 1
        nextTimestamp = time()
        newBlock = Block(index=nextIndex, previousHash=previousBlock.hash, timestamp=int(nextTimestamp), data=data)
        self.addBlockToChains(newBlock)

    def validateBlockChain(self):
        for index in [1, len(self.__chains)-1]:
            if not self.__chains[index].validateBlock(self.__chains[index - 1]):
                return False

        return True
