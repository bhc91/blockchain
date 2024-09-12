from blockchain import SigningKey, Transaction, Block, Blockchain, SECP256k1, Wallet

if __name__ == '__main__':
    # Create the blockchain
    my_blockchain = Blockchain(difficulty=2)

    # Create Joe's and Anno's wallets
    joe_wallet = Wallet()
    anno_wallet = Wallet()

    # Print Joe's and Anno's wallet addresses (public keys)
    print(f"Joe's wallet address: {joe_wallet.get_address()}")
    print(f"Anno's wallet address: {anno_wallet.get_address()}")

    # Anno sends 10 coins to Joe
    tx1 = Transaction(joe_wallet.get_address(), anno_wallet.get_address(), 10)
    joe_wallet.sign_transaction(tx1)
    my_blockchain.add_transaction(tx1)

    # Mine the transaction
    print("Start mining...")
    my_blockchain.mine_pending_transactions(joe_wallet.get_address())

    # Display balances
    print(f"Balance of Alice: {my_blockchain.get_balance(joe_wallet.get_address())}")
    print(f"Balance of Bob: {my_blockchain.get_balance(anno_wallet.get_address())}")

    # Burn 5 coins
    print("Burning coins...")
    my_blockchain.burn_coins(5)

    # Mine the burn transaction
    my_blockchain.mine_pending_transactions(joe_wallet.get_address())

    # Check balances again
    print(f"Balance of Alice: {my_blockchain.get_balance(anno_wallet.get_address())}")
    print(f"Balance of Bob: {my_blockchain.get_balance(joe_wallet.get_address())}")
    print(f"Balance of Burn Address: {my_blockchain.get_balance(my_blockchain.burn_address)}")




