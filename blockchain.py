import hashlib
import time
from ecdsa import SigningKey, VerifyingKey, SECP256k1


# Helper functions for Merkle Root
def hash_pair(first, second):
    return hashlib.sha256((first + second).encode()).hexdigest()

def get_merkle_root(transactions):
    if len(transactions) == 0:
        return '0'  # Return '0' as the Merkle root for an empty list of transactions

    if len(transactions) == 1:
        # Return the single transaction's hash as the Merkle root
        return hashlib.sha256(transactions[0].encode()).hexdigest()

    # If the number of transactions is odd, duplicate the last transaction
    if len(transactions) % 2 == 1:
        transactions.append(transactions[-1])

    new_level = []
    for i in range(0, len(transactions), 2):
        new_level.append(hash_pair(transactions[i], transactions[i + 1]))

    # Recursively compute the Merkle root of the new level
    return get_merkle_root(new_level)

def burn_coins(self, amount):
    burn_address = "0x0000000000000000000000000000000000000000"  # Burn address
    burn_transaction = Transaction(None, burn_address, amount, is_coinbase=False)
    self.pending_transactions.append(burn_transaction)
    print(f"{amount} coins will be burned.")

class Wallet:
    def __init__(self):
        # Generate a new private/public key pair
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        
        # Store the keys as hex strings
        self.private_key_hex = self.private_key.to_string().hex()
        self.public_key_hex = self.public_key.to_string().hex()

    def sign_transaction(self, transaction):
        # Sign a transaction with the wallet's private key
        transaction.sign_transaction(self.private_key_hex)

    def get_address(self):
        # The public key acts as the wallet's address
        return self.public_key_hex

# Transaction class with digital signatures
class Transaction:
    def __init__(self, sender, recipient, amount, signature=None, is_coinbase=False):
        self.sender = sender  # Sender's public key in hex
        self.recipient = recipient  # Recipient's public key in hex
        self.amount = amount  # Transaction amount
        self.signature = signature  # Digital signature
        self.is_coinbase = is_coinbase  # Coinbase transaction flag

    def calculate_hash(self):
        # Exclude the signature field when calculating the hash for signing
        return hashlib.sha256(f"{self.sender}{self.recipient}{self.amount}".encode()).hexdigest()

    def sign_transaction(self, private_key):
        if not self.sender:
            return  # Coinbase transactions don't need to be signed
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        transaction_hash = self.calculate_hash()
        self.signature = sk.sign(transaction_hash.encode()).hex()

    def is_valid(self):
        if self.is_coinbase:  # Coinbase transactions are always valid
            return True

        if not self.signature:
            raise ValueError("Transaction is not signed")

        # Verify the signature using the sender's public key
        transaction_hash = self.calculate_hash()
        vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
        try:
            return vk.verify(bytes.fromhex(self.signature), transaction_hash.encode())
        except:
            return False  # Return False if the verification fails


# Block class
class Block:
    def __init__(self, index, previous_hash, transactions, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions  # List of transactions
        self.merkle_root = self.calculate_merkle_root()  # Merkle root of transactions
        self.timestamp = timestamp or time.time()
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_merkle_root(self):
        transactions_hashes = [str(tx.__dict__) for tx in self.transactions]
        return get_merkle_root(transactions_hashes)

    def calculate_hash(self):
        # Calculate block hash using index, previous hash, Merkle root, timestamp, and nonce
        block_string = f"{self.index}{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        target = '0' * difficulty  # Target hash starts with 'difficulty' number of zeros
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")


# Blockchain class
class Blockchain:
    def __init__(self, difficulty):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []
        self.initial_mining_reward = 50
        self.halving_interval = 210000
        self.mining_interval = 2016
        self.block_time = 10 * 60
        self.burn_address = "0x0000000000000000000000000000000000000000"  # Burn address

    def create_genesis_block(self):
        return Block(0, "0", [], time.time())

    def get_latest_block(self):
        return self.chain[-1]

    def get_mining_reward(self):
        current_block_count = len(self.chain)
        halvings = current_block_count // self.halving_interval
        return self.initial_mining_reward / (2 ** halvings)

    def add_transaction(self, transaction):
        if transaction.sender and not transaction.is_valid():
            raise ValueError("Invalid transaction")
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address):
        self.adjust_difficulty()

        # Create the coinbase transaction (mining reward)
        reward = self.get_mining_reward()
        coinbase_transaction = Transaction(None, miner_address, reward, is_coinbase=True)
        self.pending_transactions.insert(0, coinbase_transaction)

        block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        block.mine_block(self.difficulty)
        self.chain.append(block)

        self.pending_transactions = []

    def burn_coins(self, amount):
        # Burn coins by sending them to the burn address
        burn_transaction = Transaction(None, self.burn_address, amount, is_coinbase=False)
        self.pending_transactions.append(burn_transaction)
        print(f"{amount} coins will be burned.")

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def adjust_difficulty(self):
        if len(self.chain) % self.mining_interval == 0 and len(self.chain) > 0:
            last_adjustment_block = self.chain[-self.mining_interval]
            time_taken = self.chain[-1].timestamp - last_adjustment_block.timestamp
            expected_time = self.mining_interval * self.block_time

            if time_taken < expected_time:
                self.difficulty += 1
            elif time_taken > expected_time:
                self.difficulty -= 1

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address:
                    balance -= transaction.amount
                if transaction.recipient == address:
                    balance += transaction.amount
        return balance