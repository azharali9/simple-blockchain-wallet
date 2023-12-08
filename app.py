from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from flask import Flask, render_template, request
import uuid  # Add this line to import the uuid module
import json  # Add this import for the json module
import flask
from flask import request, jsonify
import json


def transfer_balance(sender_username, recipient_username, amount, transaction_fee=1):
    accounts = load_accounts()

    # Check if sender and recipient usernames exist
    if sender_username not in accounts or recipient_username not in accounts:
        return jsonify({'error': 'Invalid sender or recipient username'})

    # Check if sender has enough balance
    sender_balance = get_user_balance(sender_username)
    if sender_balance < amount + transaction_fee:
        return jsonify({'error': 'Insufficient balance'})

    # Perform the balance transfer
    blockchain.mine_block(sender_username, recipient_username, amount, transaction_fee=transaction_fee)

    return redirect('dashboard')


# Load existing accounts from a JSON file
def load_accounts():
    try:
        with open('accounts.json', 'r') as f:
            accounts = json.load(f)
    except FileNotFoundError:
        accounts = {}

    return accounts



app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to a more secure secret key in production

users = {}

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=None, hash_value=None, transactions=None, merkle_tree=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash_value = hash_value
        self.transactions = transactions if transactions else []
        self.merkle_tree = merkle_tree

    def calculate_hash(self):
        data = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(data.encode()).hexdigest()

    def add_transaction(self, sender, recipient, amount):
        self.transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
    
        })


def get_username_from_public_key(public_key):
    accounts = load_accounts()
    for username, user_data in accounts.items():
        if user_data.get('public_key') == public_key:
            return username
    return None  # Return None if public key is not found



class Blockchain:
    def __init__(self):
        self.chain = [self.make_genesis_block()]
        self.difficulty = 5

    def make_genesis_block(self):
        return Block(index=0, timestamp=datetime.now(), data="Genesis Block", previous_hash="0")
    



    def get_username_from_public_key(public_key):
        accounts = load_accounts()
        for username, user_data in accounts.items():
            if user_data.get('public_key') == public_key:
                return username
        return None

    def mine_block(self, sender_public_key, recipient_public_key, amount, transaction_fee=1):
            previous_block = self.chain[-1]
            index = previous_block.index + 1
            timestamp = datetime.now()
            nonce = 0

            while True:
                nonce += 1
                block = Block(index, timestamp, f"Transaction: {sender_public_key} pays {recipient_public_key} {amount} BTC", previous_block.calculate_hash(), nonce)
                hash_value = block.calculate_hash()

                if hash_value[:self.difficulty] == "0" * self.difficulty:
                    block.hash_value = hash_value
                    block.add_transaction(sender_public_key, recipient_public_key, amount)

                    # Update the user's balance in the accounts.json file
                    update_balance(get_username_from_public_key(sender_public_key), get_username_from_public_key(recipient_public_key), amount)

                    # Calculate and add transaction fee
                    block.add_transaction("Coinbase", "Miner", transaction_fee)

                    self.chain.append(block)
                    return


    def get_balance(self, wallet_address):
                balance = 0
                for block in self.chain:
                    for transaction in block.transactions:
                        if transaction['recipient'] == wallet_address:
                            balance += transaction['amount']
                return balance

    def get_wallet_info(self, wallet_address):
                public_key, private_key = None, None
                for block in self.chain:
                    for transaction in block.transactions:
                        if transaction['recipient'] == wallet_address:
                            public_key, private_key = transaction['recipient'], transaction['sender']
                        if transaction['sender'] == wallet_address:
                            public_key, private_key = transaction['sender'], None
                return public_key, private_key



def set_initial_balance(user):
    # Set initial balance to 50 BTC
    accounts = load_accounts()
    accounts[user['username']] = {
        'password': user['password'],
        'public_key': user['public_key'],
        'private_key': user['private_key'],
        'balance': 50  # Initial balance
    }
    save_accounts(accounts)

def update_balance(sender_username, recipient_username, amount):
    accounts = load_accounts()

    # Deduct the amount from the sender's balance
    if sender_username in accounts:
        accounts[sender_username]['balance'] += amount

    # Add the amount to the recipient's balance
    if recipient_username in accounts:
        accounts[recipient_username]['balance'] -= amount

    # Save the updated user accounts to accounts.json
    save_accounts(accounts)




blockchain = Blockchain()

def load_accounts():
    try:
        with open('accounts.json', 'r') as f:
            accounts = json.load(f)
    except FileNotFoundError:
        accounts = {}

    return accounts

def save_accounts(accounts):
    # Write the updated accounts to the file
    with open("accounts.json", "w") as file:
        json.dump(accounts, file)

# Your existing routes...

def get_own_public_key():
    try:
        # Get the username from the session
        username = session.get('username')
        
        if username:
            with open('accounts.json', 'r') as f:
                accounts = json.load(f)
                return accounts.get(username, {}).get('public_key')
        else:
            return None
    except FileNotFoundError:
        return None
    
def is_valid_public_key(public_key, accounts):
    # Check if the public key starts with "public_key_" and is in the accounts
    return public_key.startswith("public_key_") and public_key in accounts



# Route to handle logout
@app.route('/logout', methods=['GET'])
def logout():
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


# Route to render the signup page
@app.route('/signup', methods=['GET'])
def signup():
    # Clear 'error' category flash messages
    flash_messages = flask.flash('error')

    # Get the remaining flash messages and pass them to the template
    remaining_flash_messages = flask.get_flashed_messages(with_categories=True)
    return render_template('signup.html', flash_messages=remaining_flash_messages)

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/signup', methods=['POST'])
def register():
    
    username = request.form.get('username')
    password = request.form.get('password')

    accounts = load_accounts()

    if not accounts:

        # Generate public and private keys
        public_key = f"public_key_{str(uuid.uuid4())[:8]}"  # Generate a random public key
        private_key = f"private_key_{str(uuid.uuid4())[:8]}"  # Generate a random private key

        # Save the new user to the users dictionary
        users[username] = {
            'password': password,
            'public_key': public_key,
            'private_key': private_key,
            'balance': 50  # Initial balance
        }

        # Save the updated user accounts to accounts.json
        save_accounts(users)

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    if username in accounts:
        flash('Username already exists. Please choose a different username.', 'error')
        return redirect(url_for('signup'))

    # Generate public and private keys
    public_key = f"public_key_{str(uuid.uuid4())[:8]}"  # Generate a random public key
    private_key = f"private_key_{str(uuid.uuid4())[:8]}"  # Generate a random private key

    # Save the new user to the users dictionary
    users[username] = {
        'password': password,
        'public_key': public_key,
        'private_key': private_key,
        'balance': 50  # Initial balance
    }

    # Save the updated user accounts to accounts.json
    save_accounts(users)

    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form.get('username')
        password = request.form.get('password')

        # Load existing accounts
        accounts = load_accounts()

        # Convert username to string for compatibility with JSON
        username = str(username)

        # Check if the password matches the stored password for the username
        if username in accounts and accounts[username]['password'] == password:
            # Store the username in the session after successful login
            session['username'] = username

            # Redirect to the dashboard page after successful login
            return redirect('dashboard')

        error = "Invalid username or password."
        return render_template('login.html', error=error)

    return render_template('login.html')




# Add a route for the root URL ("/") to render the login page
@app.route('/', methods=['GET'])
def root():
    return render_template('login.html')


def get_user_balance(username):
    accounts = load_accounts()
    user_data = accounts.get(username, {})
    return user_data.get('balance', 0)
# Add a route for the dashboard page
# Route to render the dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username')
    accounts=load_accounts()
    if username:
        # Check if the username is present in the users dictionary
        if username in accounts:
            user = accounts[username]
            blockchain = Blockchain()  # Create an instance of the Blockchain class
            #set_initial_balance(user)  # Set initial balance if not set
            public_key, private_key = user['public_key'], user['private_key']
            balance = get_user_balance(username)
            
            return render_template('index.html', public_key=user['public_key'], private_key=user['private_key'], blockchain=blockchain, balance=balance)
        else:
            flash('User not found in the users dictionary.', 'error')
    else:
        flash('User not logged in. Please log in first.', 'error')

    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
def index():
    blockchain = Blockchain()  # Assuming you have an instance of Blockchain
    public_key, private_key = blockchain.get_wallet_info(request.remote_addr)
    balance = blockchain.get_balance(public_key)
    return render_template('index.html', blockchain=blockchain, public_key=public_key, private_key=private_key, balance=balance)


@app.route('/transfer_balance', methods=['POST'])
def handle_transfer_balance():
    sender_username = session.get('username')  # Replace with the actual sender's username
    recipient_username = request.form['recipient_username']
    amount = float(request.form['amount'])

    result = transfer_balance(sender_username, recipient_username, amount, transaction_fee=1.0)
    return result

@app.route('/send_btc', methods=['POST'])
def send_btc():
    sender_private_key, sender_public_key = generate_key_pair()
    sender_wallet_address = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    recipient_address = request.form.get('recipient')  # Fix: Use parentheses instead of square brackets
    amount = float(request.form.get('amount'))  # Fix: Use parentheses instead of square brackets
    transaction_fee = 1.5  # You can adjust the fee as needed
    username = session.get('username')

    try:
        blockchain.mine_block(sender_wallet_address, recipient_address, amount, transaction_fee=transaction_fee)
        return render_template('index.html', blockchain=blockchain, public_key=sender_wallet_address, private_key=sender_private_key, balance=blockchain.get_balance(recipient_address))
    except Exception as e:
        return render_template('index.html', error=str(e))


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

if __name__ == '__main__':

  
    # Generate a public/private key pair for the server
    private_key_server, public_key_server = generate_key_pair()

    # Serialize the public key before writing it to the file
    serialized_public_key = public_key_server.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the server's public key to a file
    with open("server_public_key.pem", "wb") as key_file:
        key_file.write(serialized_public_key)

    app.run(debug=True)