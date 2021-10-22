import rsa
import hashlib
from datetime import datetime
#from Crypto.PublicKey import RSA


class User:

    def __init__(self, name, credit):
        self.name = name
        self.credit = credit
        self.pubkey, self.__privkey = rsa.newkeys(512)

    #        key = RSA.generate(2048)
    #        self.p_key = key.publickey().exportKey("PEM")
    #        self.priv_key = key.exportKey("PEM")

    def __str__(self):
        return f"{self.name} has {self.credit} credit \nUser's public key: \n{self.pubkey} \nUser's private key: \n{self.__privkey}"

    def getPublicKey(self):
        return self.pubkey

    def getPrivateKey(self):
        return self.__privkey


class Transaction:
    def __init__(self, sender, receiver, amount):
        self.timestamp = datetime.now()
        self.sender = User(sender, amount)
        self.receiver = User(receiver, amount)
        self.amount = amount

    def sign(self):
        # signature = rsa.sign(str(transaction).encode(), self.sender.getPrivateKey(), 'SHA-256')
        signature = rsa.sign(str(self.timestamp).encode(), self.sender.getPrivateKey(), 'SHA-256')
        return signature
        ##return signature.hex()

    def verify(self, signature):
        try:
            rsa.verify(str(self).encode(), signature, self.sender.getPublicKey())
            return True
        except rsa.pkcs1.VerificationError:
            return False


class MerkleTreeBuilder:
    def __init__(self):
        pass

    def getRoot(self, hashes):
        if len(hashes) == 1:                                    # páratlanok számú levélcsomópont
            return hashes[0].hex()

        if len(hashes) % 2 != 0:                                # páros számú levélcsomópont
            hashes.append(hashes[-1])

        new_hashes = []
        for i in range(0, len(hashes) - 1, 2):
            h = hashlib.sha256()
            h.update(hashes[i] + hashes[i + 1])
            new_hashes.append(h.digest())
        return self.getRoot(new_hashes)


class Block:
    def __init__(self, prev_block_hash,actual_block_hash):                          #blokk száma, előző blokk hashe, tranzakciók hashe
        self.prev_block_hash = prev_block_hash
        self.actual_block_hash = actual_block_hash
        self.nonce = 0                                                              #egyszer használatos random szám, korlátozza a nehézségi szintet

    def __str__(self):
        return f"Hash of previous block: {self.prev_block_hash}\nHash of actual block:   {self.actual_block_hash}\nNonce: {self.nonce}"

    def getHash(self):
        h = hashlib.sha256()                                                #kezelőfelület biztosít az sha256 biztonságos hash algoritmusainak
        h.update(str(self).encode())                                        #h frissül az eredmény string formájánának bájt formátumával
        return h.hexdigest()

    def mineBlock(self, difficulty):
        zeros = '0' * difficulty
        while (self.getHash()[0:difficulty] != zeros):
            self.nonce += 1
        return self.getHash()

    def prev_hash(self):
        return self.prev_block_hash

    def get_hash(self):
        h = hashlib.sha256()
        h.update(str(self).encode())
        return h.hexdigest()


class Blockchain:
    def __init__(self, difficulty):
        self.blocks = []
        self.difficulty = difficulty
        self.actual_block_number = 0
        block0 = Block(0, '0' * 64)
        block0.mineBlock(self.difficulty)
        self.appendBlock(block0)

    def getLastBlock(self):
        return self.blocks[self.actual_block_number - 1]

    def appendBlock(self, block):
        self.blocks.append(block)
        self.actual_block_number += 1


def main():
    user_Marika = User("Marika", 100)
    user_Katika = User("Katika", 100)
    user_Erzso = User("Erzso", 100)
    user_Irenke = User("Irenke", 100)

    transactions = []
    transactions.append(Transaction(user_Marika, user_Irenke, 10))
    transactions.append(Transaction(user_Erzso,user_Katika,50))
    transactions.append(Transaction(user_Katika,user_Marika,35))
    transactions.append(Transaction(user_Irenke,user_Erzso,20))

    signatures = []
    signatures.append(transactions[0].sign())
    signatures.append(transactions[1].sign())
    signatures.append(transactions[2].sign())
    signatures.append(transactions[3].sign())

    # print(transactions[0].sign())
    # print(signatures[0])

    # for i in range(len(signatures)):
    #    print(transactions[i].verify(signatures[i]))

    mtb = MerkleTreeBuilder()

    merkle_root = mtb.getRoot(signatures)

    # blocks = []
    # blocks.append(Block("","",""))

    # print(blocks[0].getPrevHash())

    blockchain = Blockchain(4)
    print(blockchain.getLastBlock())
#    print("Hash of current block:", blockchain.getLastBlock().getHash())

    block = Block( blockchain.getLastBlock().getHash(), merkle_root)
    block.mineBlock(blockchain.difficulty)
    print(block)
    print("Hash of last block:    ", block.getHash(),"\n")
    blockchain.appendBlock(block)





    transactions.append(Transaction(user_Marika, user_Irenke, 10))
    transactions.append(Transaction(user_Erzso,user_Katika,50))
    transactions.append(Transaction(user_Katika,user_Marika,35))
    transactions.append(Transaction(user_Irenke,user_Erzso,20))

    signatures.append(transactions[4].sign())
    signatures.append(transactions[5].sign())
    signatures.append(transactions[6].sign())
    signatures.append(transactions[7].sign())

    merkle_root = mtb.getRoot(signatures)

    block = Block(blockchain.getLastBlock().getHash(), merkle_root)
    block.mineBlock(blockchain.difficulty)
    print(block)
    print("Hash of last block:    ", block.getHash(),"\n")
    blockchain.appendBlock(block)






    transactions.append(Transaction(user_Marika, user_Irenke, 10))
    transactions.append(Transaction(user_Erzso, user_Katika, 50))
    transactions.append(Transaction(user_Katika, user_Marika, 35))
    transactions.append(Transaction(user_Irenke, user_Erzso, 20))

    signatures.append(transactions[8].sign())
    signatures.append(transactions[9].sign())
    signatures.append(transactions[10].sign())
    signatures.append(transactions[11].sign())

    merkle_root = mtb.getRoot(signatures)

    block = Block(blockchain.getLastBlock().getHash(), merkle_root)
    block.mineBlock(blockchain.difficulty)
    print(block)
    print("Hash of last block:    ", block.getHash(),"\n")
    blockchain.appendBlock(block)

if __name__ == "__main__":
    main()