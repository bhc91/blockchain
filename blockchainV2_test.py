from blockchainV2 import Blockchain, Wallet, Transaction, TransactionInput, TransactionOutput

def test_blockchain():
    # Erstelle eine Blockchain
    blockchain = Blockchain()

    # Erstelle zwei Wallets
    wallet_sender = Wallet()
    wallet_recipient = Wallet()

    # Mine einen Block, um Coins zu erhalten
    miner_wallet = Wallet()
    blockchain.mine_block(miner_wallet.get_address())

    # Überprüfe den Kontostand des Miners
    miner_balance = blockchain.get_balance(miner_wallet.get_address())
    print(f"Miner Balance: {miner_balance / 10**8} BTC")

    # Erstelle eine Transaktion vom Miner zum Sender
    utxos = [utxo for utxo in blockchain.utxos.values() if utxo.script_pub_key == blockchain.address_to_script_pub_key(miner_wallet.get_address())]
    if not utxos:
        print("Keine verfügbaren UTXOs für den Miner.")
        return
    input_utxo = utxos[0]

    tx_in = TransactionInput(input_utxo.txid, input_utxo.index)
    amount_to_send = int(25 * 10**8)  # 25 BTC in Satoshi
    tx_out1 = TransactionOutput(amount_to_send, blockchain.address_to_script_pub_key(wallet_sender.get_address()))
    change_amount = input_utxo.amount - amount_to_send
    tx_out2 = TransactionOutput(change_amount, blockchain.address_to_script_pub_key(miner_wallet.get_address()))
    transaction = Transaction([tx_in], [tx_out1, tx_out2])

    # Signiere die Transaktion
    transaction.sign_input(0, miner_wallet.private_key, input_utxo.script_pub_key)

    # Füge die Transaktion zum Mempool hinzu
    blockchain.add_transaction(transaction)

    # Mine einen weiteren Block
    blockchain.mine_block(miner_wallet.get_address())

    # Überprüfe die Kontostände
    miner_balance = blockchain.get_balance(miner_wallet.get_address())
    sender_balance = blockchain.get_balance(wallet_sender.get_address())
    print(f"Miner Balance: {miner_balance / 10**8} BTC")
    print(f"Sender Balance: {sender_balance / 10**8} BTC")

    # Mine weitere Blöcke, um die Schwierigkeitsanpassung zu testen
    for i in range(15):
        blockchain.mine_block(miner_wallet.get_address())
        print(f"Block {len(blockchain.chain)} gemined. Aktuelle Schwierigkeit: {hex(blockchain.difficulty)}")

if __name__ == "__main__":
    test_blockchain()

