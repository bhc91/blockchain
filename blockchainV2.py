import hashlib
import time
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import base58

# Helper-Funktionen
def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

def hash160(data):
    return ripemd160(sha256(data))

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58_check_encode(data):
    checksum = double_sha256(data)[:4]
    return base58.b58encode(data + checksum).decode()

def base58_check_decode(data):
    decoded = base58.b58decode(data)
    data, checksum = decoded[:-4], decoded[-4:]
    if double_sha256(data)[:4] != checksum:
        raise ValueError("Invalid checksum")
    return data

def hash_pair(first, second):
    return hashlib.sha256(first + second).digest()

def get_merkle_root(transactions):
    if len(transactions) == 0:
        return b'\x00' * 32  # Leerer Merkle Root

    layer = [double_sha256(tx.serialize()) for tx in transactions]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # Dupliziere letztes Element bei ungerader Anzahl

        new_layer = []
        for i in range(0, len(layer), 2):
            new_layer.append(double_sha256(layer[i] + layer[i + 1]))
        layer = new_layer

    return layer[0]

# UTXO-Klasse
class UTXO:
    """
    Repräsentiert einen ungenutzten Transaktionsausgang (Unspent Transaction Output).
    """
    def __init__(self, txid, index, amount, script_pub_key):
        self.txid = txid
        self.index = index
        self.amount = amount
        self.script_pub_key = script_pub_key

    def serialize(self):
        return self.txid + self.index.to_bytes(4, 'big') + self.amount.to_bytes(8, 'big') + self.script_pub_key

# Wallet-Klasse
class Wallet:
    """
    Repräsentiert eine Wallet mit privaten und öffentlichen Schlüsseln.
    """
    def __init__(self):
        # Generiere neuen privaten/public Key
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def get_address(self):
        """
        Generiert die Bitcoin-Adresse aus dem öffentlichen Schlüssel.
        """
        pub_key_bytes = self.public_key.to_string()
        hashed_pub_key = hash160(pub_key_bytes)
        versioned_payload = b'\x00' + hashed_pub_key  # \x00 für Mainnet
        address = base58_check_encode(versioned_payload)
        return address

    def sign(self, data):
        """
        Signiert die gegebenen Daten mit dem privaten Schlüssel.
        """
        return self.private_key.sign(data, hashfunc=hashlib.sha256)

# Transaktions-Klassen
class TransactionInput:
    """
    Repräsentiert einen Transaktionseingang.
    """
    def __init__(self, txid, index, script_sig=b''):
        self.txid = txid
        self.index = index
        self.script_sig = script_sig

    def serialize(self):
        return self.txid + self.index.to_bytes(4, 'big') + len(self.script_sig).to_bytes(1, 'big') + self.script_sig

class TransactionOutput:
    """
    Repräsentiert einen Transaktionsausgang.
    """
    def __init__(self, amount, script_pub_key):
        self.amount = amount
        self.script_pub_key = script_pub_key

    def serialize(self):
        return self.amount.to_bytes(8, 'big') + len(self.script_pub_key).to_bytes(1, 'big') + self.script_pub_key

# Transaction-Klasse
class Transaction:
    """
    Repräsentiert eine Transaktion mit Eingängen und Ausgängen.
    """
    def __init__(self, inputs, outputs, is_coinbase=False):
        self.inputs = inputs  # Liste von TransactionInput
        self.outputs = outputs  # Liste von TransactionOutput
        self.is_coinbase = is_coinbase

    def serialize(self):
        result = b''
        result += len(self.inputs).to_bytes(1, 'big')
        for tx_in in self.inputs:
            result += tx_in.serialize()
        result += len(self.outputs).to_bytes(1, 'big')
        for tx_out in self.outputs:
            result += tx_out.serialize()
        return result

    def txid(self):
        return double_sha256(self.serialize())

    def sign_input(self, input_index, private_key, utxo_script_pub_key):
        """
        Signiert einen bestimmten Eingang der Transaktion.
        """
        tx_copy = self.copy_for_signing(input_index, utxo_script_pub_key)
        tx_copy_serialized = tx_copy.serialize()
        signature = private_key.sign(tx_copy_serialized, hashfunc=hashlib.sha256)
        pubkey = private_key.get_verifying_key().to_string()
        signature_script = (
            len(signature).to_bytes(1, 'big') +
            signature +
            len(pubkey).to_bytes(1, 'big') +
            pubkey
        )
        self.inputs[input_index].script_sig = signature_script

    def copy_for_signing(self, input_index, utxo_script_pub_key):
        inputs = []
        for i, tx_in in enumerate(self.inputs):
            if i == input_index:
                inputs.append(TransactionInput(tx_in.txid, tx_in.index, utxo_script_pub_key))
            else:
                inputs.append(TransactionInput(tx_in.txid, tx_in.index, b''))
        return Transaction(inputs, self.outputs, self.is_coinbase)

# Block-Klassen
class BlockHeader:
    """
    Repräsentiert den Header eines Blocks.
    """
    def __init__(self, version, previous_hash, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def serialize(self):
        result = b''
        result += self.version.to_bytes(4, 'little')
        result += self.previous_hash
        result += self.merkle_root
        result += self.timestamp.to_bytes(4, 'little')
        result += self.bits.to_bytes(4, 'little')
        result += self.nonce.to_bytes(4, 'little')
        return result

    def hash(self):
        return double_sha256(self.serialize())

class Block:
    """
    Repräsentiert einen Block, bestehend aus einem Header und Transaktionen.
    """
    def __init__(self, header, transactions):
        self.header = header
        self.transactions = transactions

    def serialize(self):
        result = self.header.serialize()
        result += len(self.transactions).to_bytes(1, 'big')
        for tx in self.transactions:
            result += tx.serialize()
        return result

# Blockchain-Klasse
class Blockchain:
    """
    Repräsentiert die Blockchain, die aus einer Kette von Blöcken besteht.
    """
    def __init__(self):
        self.chain = []
        self.difficulty = 0x1f3fffff  
        self.utxos = {}
        self.mempool = []
        self.halving_interval = 210000
        self.initial_reward = 50 * 10**8
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Erstellt den Genesis-Block der Blockchain.
        """
        # Verwenden Sie eine bekannte Adresse oder generieren Sie eine
        genesis_wallet = Wallet()
        genesis_address = genesis_wallet.get_address()
        coinbase_tx = Transaction([], [TransactionOutput(self.get_mining_reward(), self.address_to_script_pub_key(genesis_address))], is_coinbase=True)
        genesis_block_header = BlockHeader(
            version=1,
            previous_hash=b'\x00' * 32,
            merkle_root=get_merkle_root([coinbase_tx]),
            timestamp=int(time.time()),
            bits=self.difficulty,
            nonce=0
        )
        genesis_block = Block(genesis_block_header, [coinbase_tx])
        self.chain.append(genesis_block)
        self.update_utxos(genesis_block)

    def get_mining_reward(self):
        """
        Berechnet die aktuelle Blockbelohnung basierend auf der Blockhöhe und Halvings.
        """
        current_height = len(self.chain)
        halvings = current_height // self.halving_interval
        if halvings >= 64:
            return 0  # Nach 64 Halvings ist die Belohnung 0
        return int(self.initial_reward / (2 ** halvings))

    def add_transaction(self, transaction):
        """
        Fügt eine Transaktion zum Mempool hinzu, nachdem sie validiert wurde.
        """
        if not self.validate_transaction(transaction):
            raise ValueError("Ungültige Transaktion")
        self.mempool.append(transaction)

    def mine_block(self, miner_address):
        """
        Führt den Mining-Prozess durch und fügt den neuen Block zur Blockchain hinzu.
        """
        reward = self.get_mining_reward()
        coinbase_tx = Transaction([], [TransactionOutput(reward, self.address_to_script_pub_key(miner_address))], is_coinbase=True)
        block_transactions = [coinbase_tx] + self.mempool
        merkle_root = get_merkle_root(block_transactions)

        previous_hash = self.chain[-1].header.hash()

        block_header = BlockHeader(
            version=1,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            timestamp=int(time.time()),
            bits=self.difficulty,
            nonce=0
        )

        block = Block(block_header, block_transactions)

        target = self.bits_to_target(self.difficulty)

        # Begrenzen Sie die Anzahl der Versuche für schnellere Tests
        max_nonce = 500000
        while int.from_bytes(block.header.hash(), 'big') > target and block.header.nonce < max_nonce:
            block.header.nonce += 1
            if block.header.nonce % 1000 == 0:
                block.header.timestamp = int(time.time())

        if int.from_bytes(block.header.hash(), 'big') > target:
            print("Block konnte nicht innerhalb des Nonce-Limits gemined werden.")
            return  # Mining fehlgeschlagen für diesen Durchlauf

        print(f"Block gemined: {block.header.hash().hex()}")
        self.chain.append(block)
        self.update_utxos(block)
        self.mempool = []

        # Schwierigkeitsanpassung nach dem Hinzufügen des Blocks
        self.adjust_difficulty()

    def update_utxos(self, block):
        """
        Aktualisiert das UTXO-Set basierend auf den Transaktionen im Block.
        """
        for tx in block.transactions:
            tx_id = tx.txid()
            # Entferne verbrauchte UTXOs
            if not tx.is_coinbase:
                for tx_in in tx.inputs:
                    key = (tx_in.txid, tx_in.index)
                    if key in self.utxos:
                        del self.utxos[key]
            # Füge neue UTXOs hinzu
            for index, tx_out in enumerate(tx.outputs):
                key = (tx_id, index)
                self.utxos[key] = UTXO(tx_id, index, tx_out.amount, tx_out.script_pub_key)

    def validate_transaction(self, tx):
        if tx.is_coinbase:
            return True

        input_amount = 0
        for tx_in in tx.inputs:
            key = (tx_in.txid, tx_in.index)
            if key not in self.utxos:
                print("UTXO nicht gefunden")
                return False
            utxo = self.utxos[key]
            # Überprüfe ScriptSig und ScriptPubKey (P2PKH)
            # Extrahiere Signatur und öffentlichen Schlüssel aus script_sig
            script_sig = tx_in.script_sig
            try:
                sig_len = script_sig[0]
                signature = script_sig[1:1+sig_len]
                pubkey_len = script_sig[1+sig_len]
                pubkey = script_sig[1+sig_len+1:1+sig_len+1+pubkey_len]
            except IndexError:
                print("Fehler beim Parsen von script_sig")
                return False

            # Hash des öffentlichen Schlüssels berechnen
            pubkey_hash = hash160(pubkey)
            # Vergleiche den Hash des öffentlichen Schlüssels mit dem script_pub_key des UTXO
            if pubkey_hash != utxo.script_pub_key:
                print("Public Key Hash stimmt nicht überein")
                return False

            # Signatur verifizieren
            vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
            # Übergib utxo_script_pub_key beim Aufruf von copy_for_signing
            tx_copy = tx.copy_for_signing(tx.inputs.index(tx_in), utxo.script_pub_key)
            tx_copy_serialized = tx_copy.serialize()
            try:
                if not vk.verify(signature, tx_copy_serialized, hashfunc=hashlib.sha256):
                    print("Signatur ungültig")
                    return False
            except Exception as e:
                print(f"Fehler bei der Signaturprüfung: {e}")
                return False

            input_amount += utxo.amount

        output_amount = sum(tx_out.amount for tx_out in tx.outputs)
        if input_amount < output_amount:
            print("Eingabebetrag kleiner als Ausgabebetrag")
            return False

        return True

    def get_balance(self, address):
        """
        Berechnet den Kontostand für eine gegebene Adresse.
        """
        balance = 0
        script_pub_key = self.address_to_script_pub_key(address)
        for utxo in self.utxos.values():
            if utxo.script_pub_key == script_pub_key:
                balance += utxo.amount
        return balance

    def address_to_script_pub_key(self, address):
        """
        Wandelt eine Adresse in das entsprechende script_pub_key um.
        """
        payload = base58_check_decode(address)
        return payload[1:]  # Entferne die Versionsbyte

    def bits_to_target(self, bits):
        """
        Wandelt die Bits in das entsprechende Mining-Ziel um.
        """
        exponent = bits >> 24
        mantissa = bits & 0xffffff
        target_hexstr = '%064x' % (mantissa * (1 << (8 * (exponent - 3))))
        return int(target_hexstr, 16)

    def adjust_difficulty(self):
        """
        Passt die Schwierigkeit basierend auf der Zeit an, die zum Mining der letzten Blöcke benötigt wurde.
        """
        adjustment_interval = 10  # Für schnelle Tests
        if len(self.chain) % adjustment_interval == 0 and len(self.chain) >= adjustment_interval:
            last_block = self.chain[-1]
            first_block = self.chain[-adjustment_interval]
            time_diff = last_block.header.timestamp - first_block.header.timestamp
            expected_time = adjustment_interval * 2  # Erwartete Zeit in Sekunden

            # Verhindern von extremen Anpassungen
            if time_diff < expected_time / 4:
                time_diff = expected_time / 4
            elif time_diff > expected_time * 4:
                time_diff = expected_time * 4

            new_difficulty = int(self.difficulty * (expected_time / time_diff))
            if new_difficulty < 1:
                new_difficulty = 1  # Mindestschwierigkeit
            self.difficulty = new_difficulty
            print(f"Neue Schwierigkeit: {hex(self.difficulty)}")
