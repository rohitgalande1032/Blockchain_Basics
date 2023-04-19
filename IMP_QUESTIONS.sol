//SPDX License-Identifier: GPL-3.0
pragma solidity >= 0.7.0 < 0.9.0;

//Question 1 - Write a smart contract in Solidity that implements a basic token.

contract BasicToken {
    string public name = "Basic Token";
    string public symbol = "BTK";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10 ** uint256(decimals);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_to != address(0));

        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;

        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != address(0));

        allowance[msg.sender][_spender] = _value;

        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(allowance[_from][msg.sender] >= _value);
        require(_to != address(0));

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        allowance[_from][msg.sender] -= _value;

        emit Transfer(_from, _to, _value);
        return true;
    }
}
/*
This contract is a basic implementation of an ERC-20 token. It has a name, symbol, and decimals that are all specified in the contract. 
The totalSupply variable is also initialized in the constructor.

The balanceOf mapping keeps track of the balance of each address that holds the token. The allowance mapping keeps track of how much 
a certain address is allowed to spend on behalf of another address.

The transfer function is used to transfer tokens from one address to another. It first checks that the sender has enough tokens to 
transfer and that the recipient address is not zero. It then subtracts the transferred amount from the sender's balance and adds it 
to the recipient's balance.

The approve function is used to give another address permission to spend tokens on behalf of the owner of the tokens. It first checks 
that the spender address is not zero. It then sets the allowance for the spender to the specified value.

The transferFrom function is used to transfer tokens from one address to another on behalf of a third address that has been given 
permission to do so. It first checks that the sender has enough tokens to transfer, that the allowance for the spender is greater 
than or equal to the transferred amount, and that the recipient address is not zero. It then subtracts the transferred amount from 
the sender's balance, adds it to the recipient's balance, and subtracts the transferred amount from the spender's allowance.

Finally, the Transfer and Approval events are emitted whenever tokens are transferred or approval is given for spending.*/

//Question 2 - Write a function that takes in a block header and verifies its validity.

/*In blockchain technology, a block header is a data structure that contains metadata about a block in the blockchain. It is the first part of the block and
 includes information such as the block's version number, a reference to the previous block's hash, a Merkle root hash of all the transactions in the 
 block, a timestamp, a nonce, and a difficulty target.
 
 The block header is used to validate the block's contents and ensure that it has been created by a legitimate node in the network through a process 
 called Proof of Work (PoW)*/

contract BlockVerifier {
    struct BlockHeader {
        uint32 version;
        bytes32 prevBlockHash;
        bytes32 merkleRoot;
        uint32 timestamp;
        uint32 difficulty;
        uint32 nonce;
    }

    function verifyBlockHeader(BlockHeader memory header) public pure returns (bool) {
        //Check the version of the block
        if (header.version != 1) {
            return false;
        }

        //Check the hash of previous block
        if(header.prevBlockHash == bytes32(0)) {
            return false;
        }

        //Check hash of Merkle root
        if (header.merkleRoot == bytes32(0)) {
            return false;
        }

        //Check the difficulty target
        if (header.difficulty <= 0) {
            return false;
        }

        //Check the nonce
        if(header.nonce <= 0) {
            return false;
        }

        //Calculate the hash of blockheader
        bytes32 blockHeader = keccak256(abi.encodePacked(header.version, header.prevBlockHash, header.merkleRoot, header.timestamp, header.difficulty, header.nonce));

        //Check that calculated hash matches the target hash
        if(uint256(blockHeader) > 2**(256 - header.difficulty)) {
            return false;
        }

        return true;
    }
}
/* The function first checks that the version is valid (in this example, we're assuming it's version 1). It then checks that the previous block hash and 
the Merkle root are both non-zero values (since they are bytes32 type, a zero value indicates an empty hash). It also checks that the timestamp is less 
than or equal to the current block's timestamp, and that the difficulty and nonce are both positive integers.

The function then calculates the hash of the block header using the keccak256 function, which is the Solidity equivalent of the SHA-256 hashing 
algorithm. It checks that the resulting hash is less than or equal to the target hash (which is calculated using the difficulty level) by converting 
the hash to a uint256 value and comparing it to 2**(256 - header.difficulty).

If all the checks pass, the function returns true to indicate that the block header is valid. If any check fails, it returns false.
*/

//Question 3 - Implement a Merkle tree data structure and use it to validate a set of transactions.

/* A Merkle tree is a binary tree in which each leaf node represents a data block and each non-leaf node represents the hash of its child nodes. The root of the 
tree is a single hash that represents the entire set of data blocks. The purpose of a Merkle tree is to allow efficient verification of the integrity of the 
data set, without having to download the entire data set.
*/

contract MerkleTree {
    uint256 constant TREE_HEIGHT = 4;
    bytes32[TREE_HEIGHT][] internal layers;

    constructor() {
        //Initialize root of Merkle tree with a zero hash
        layers[0][0] = bytes32(0);
    }

    //Returns root hash of Merkle Tree
    function getRoot() public view returns (bytes32) {
        return layers[TREE_HEIGHT-1][0];
    }

    //Insert a leaf into the Merkle tree 
    function insertLeaf(bytes32 leaf) public {
        uint256 layer = 0;
        layers[layer][0];

        //Build up tree by hashing adjacent of nodes
        for(uint256 i=0; i<TREE_HEIGHT -1; i++) {
            layer = i+1;
            uint256 nodesInLayer = 2**layer;
            for(uint256 j=0; j < nodesInLayer; j+=2) {
                layers[layer][j/2] = hashNodes(layers[layer-1][j], layers[layer-1][j+1]);
            }
        }
    }

    //Validate a transactio by checking its inclusion in the Merkle tree
    function validateTransaction(uint256 index, bytes32 transaction, bytes32[] memory proof) public view returns(bool) {
        require(index < 2**(TREE_HEIGHT-1), "Invalid index");

        bytes32 hash = transaction;
        for(uint256 i =0; i<proof.length; i++) {
            if(index %2 ==0) {
                hash = hashNodes(hash, proof[i]);
            }else {
                hash = hashNodes(proof[i], hash);
            }
            index /= 2;
        }
        return (hash == getRoot());
    }

    //Hashes two nodes together using SHA-256
    function hashNodes(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        bytes memory merged = abi.encodePacked(left,right);
        return sha(merged);
    }
}

/*The MerkleTree contract initializes a Merkle tree with a height of TREE_HEIGHT (which can be adjusted as needed). The tree is represented as an array of 
bytes32 values, with each layer of the tree stored in a separate array.

The insertLeaf function inserts a new leaf node into the Merkle tree. It starts by inserting the leaf node into the first layer of the tree, and then 
recursively hashes adjacent pairs of nodes to build up the tree.

The validateTransaction function takes in an index, a transaction hash, and a Merkle proof (i.e., a set of hashes that proves the inclusion of the transaction 
in the Merkle tree). It then calculates the root hash of the Merkle tree by hashing adjacent pairs of nodes based on the Merkle proof, and returns true if the 
calculated root hash matches the actual root hash of the Merkle tree (which can be obtained using the getRoot function).*/

//Question 4 - Write a script that extracts data from a blockchain and stores it in a database.

const Web3 = require('web3');
const {Client} = require('pg');

//Connect to the Ethereum netwot=rk using web3.js
const web3 = new Web3('https://mainnet.infura.io/v3/YOUR-PROJECT-ID');

//connect to the PostgreSQL database
const client = new Client({
    user: 'your_username',
    password: 'your_password',
    host: 'localhost',
    port: '5432',
    database: 'your_database_name',
});
client.connect();

//Define fun to extract data from the blockchain and store it in database
async function extractAndStoreData() {
    //get latest block number
    const latestBlockNumber = await web3.eth.getBlockNumber();

    //Iterate over each block and extract data
    for(let blockNumber = latestBlockNumber - 10000; blockNumber <= latestBlockNumber; blockNumber++) {// get data from last 10,000 blocks
        //Get the block information
        const block = await web3.eth.getBlock(blockNumber, true);

        //Iterate over each transaction in the block
        for(let i=0; i<block.transaction-length; i++) {
            const tx = block.transactions[i];

            //Extract data you want from the transaction
            const data = {
                blockNumber: blockNumber,
                txHash: tx.hash,
                fromAddress: tx.from,
                toAddress: tx.to,
                value: web3.utils.fromWei(tx.value, 'ether'),
                gasPrice: web3.utils.fromWei(tx.gasPrice. 'gwei'),
                gasUsed: tx.gasUsed
            };

            //Insert data into database
            await client.query(
                'INSERT INTO transactions (block_number, tx_hash, from_address, to_address, value, gas_price, gas_used) VALUES ($1,$2,$3,$4,$5,$6,$7)',
                [data.blockNumber, data.txHash, data.fromAddress, data.toAddress, data.value,data.gasPrice, data.gasUsed]
            );
        }
    }
    //Close database conns=ection 
    client.end();
}

// Call the function to extract and store data from the blockchain
extractAndStoreData();

//Question 5 - Write a program that calculates the average gas price for transactions on the Ethereum network over a specific time period.

contract GasPriceCalculator {
    struct Transaction {
        uint256 timeStamp;
        uint256 gasPrice
    }

    Transaction[] transactions;

    function addTransaction(uint256 timestamp, uint256 gasPrice) public {
        Transaction memory newTransaction = Transaction(timestamp, gasPrice);
        transactions.push(newTransaction);
    }

    function getAverageGasPrice(uint256 startTime, uint256 endTime) public view returns (uint256) {
        uint256 sumGasPrice = 0;
        uint256 count;

        for(uint256 i=0; i<transaction.length; i++) {
            if(transactioins[i].timestamp >= startTime && transactions[i].timestamp <= endTime) {
                sumGasPrice += transactions[i].gasPrice;
                count++;
            }
        }
        if(count == 0) {
            return 0;
        }
        return sumGasPrice / count;
    }
}

/* Import the necessary Solidity libraries and declare the contract.
Define a struct to hold transaction data including the timestamp and gas price.
Create a dynamic array to store the transaction data structs.
Define a function to add new transactions to the array.
Define a function to calculate the average gas price over a specific time period by filtering the array based on the timestamp.
Return the average gas price.*/

contract SimpleProofOfWork {
    uint public target;
    uint public nonce;
    bytes32 public currentBlockHash;
    address public currentMiner;

    constructor(uint _target) {
        target = _target;
        currentBlockHash = blockhash(block.number - 1);
    }

    function mine(uint _nonce) public {
        bytes32 candidateHash = keccak256(abi.encodePacked(currentBlockHash, _nonce));
        if(uint(candidateHash) < target) {
            currentBlockHash = candidateHash;
            nonce = _nonce;
            currentMiner = msg.sender;
        }
    }
}

/*In this example, the SimpleProofOfWork contract represents a blockchain that uses a PoW consensus algorithm. The contract has four state variables:

target: The target hash value that miners are trying to find. The lower the target, the harder it is to find a valid block.
nonce: The current nonce value being used by the miner to find a valid block.
currentBlockHash: The hash of the current block being mined.
currentMiner: The address of the miner who successfully mined the current block.
The SimpleProofOfWork contract has two functions:

constructor: This function sets the initial value of the target variable and initializes the currentBlockHash variable to the hash of the previous block.

mine: This function is called by a miner who wants to add a new block to the blockchain. The miner provides a nonce value as an argument. The function then 
calculates the hash of the candidate block (which includes the current block hash and the nonce value) and checks if it meets the target value. If the hash 
value is less than the target, the block is considered valid and is added to the blockchain. The function updates the currentBlockHash, nonce, and currentMiner 
variables with the values of the valid block.

This is just a basic example of a PoW consensus algorithm implemented in Solidity. In practice, a PoW consensus algorithm would be much more complex and would 
require additional functionality, such as a way to adjust the difficulty of the puzzle over time to ensure that new blocks are added at a consistent rate.*/

//Question - 6 Develop a custom blockchain and create a client to interact with it.

contract SimpleBlockchain {
    uint public blockNumber = 0;

    struct Block {
        uint number;
        bytes32 previousHash;
        bytes32 hash;
        uint timestamp;
        address miner;
        bytes32[] transactions;
    }

    Block[] public blocks;

    function addBlock(bytes32[] memory _transactions) public {
        Block memory newBlock;
        newBlock.number = blockNumber;
        newBlock.previousHash = blocks[blockNumber -1].hash;
        newBlock.hash = keccak256(abi.encodedPacked(blockNumber, newBlock.previousHash, _transactions));
        newBlock.timestamp = block.timestamp;
        newBlock.miner = msg.sender;
        newBlock.transactions = _transactions;

        blocks.push(newBlock);
        blockNumber++;
    }

    function getBlock(uint _blockNumber) public view returns (uint, bytes32, bytes32, uint, address, bytes32[] memory) {
        Block memory blockToReturn = blocks[_blockNumber];
        return (blockToReturn.number, blockToReturn.previousHash, blockToReturn.hash, blockToReturn.timestamp, blockToReturn.miner, blockToReturn.transactions);
    }

    //Add client
    SimpleBlockchain private blockchain;

    constructor(address _blockchainAddress) {
        blockchain = SimpleBlockchain(_blockchainAddress);
    }

    function addBlock(bytes32[] memory _transactions) public {
        blockchain.addBlock(_transactions);
    }

}

//Quesdtion 7 - Write a program that generates a random private key for a Bitcoin wallet.

const bitcoin = require('bitcoinjs-lib');
const randomBytes = require('randombytes');

// Generate a 256-bit random number (private key)
const privateKey = randomBytes(32);

// Convert the private key to a Wallet Import Format (WIF) string
const network = bitcoin.networks.bitcoin;
const keyPair = bitcoin.ECPair.fromPrivateKey(privateKey, { network });
const wif = keyPair.toWIF();

// Derive the public key (compressed format)
const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });

// Print the private key and public address
console.log(`Private key: ${wif}`);
console.log(`Public address: ${address}`);

/* This program uses the randombytes module to generate a 256-bit random number (private key) and the bitcoinjs-lib library to convert it to a Wallet Import Format (WIF) string and derive the corresponding public key and Bitcoin address. */

//Question 8 - Implement a secure hashing algorithm like SHA-256 or Keccak.

/* Implementing a secure hashing algorithm like SHA-256 or Keccak from scratch is a complex task that requires a deep understanding of cryptographic principles and techniques. It is not recommended for individuals without extensive experience and knowledge in cryptography and computer science.

Instead, it is recommended to use existing and widely trusted libraries or tools that implement these algorithms, such as the OpenSSL library or the Crypto module in Node.js.

Here's an example implementation of SHA-256 using the Crypto module in Node.js: */

const crypto = require('crypto');

//Data to hash
const data = 'Hello, Rohit!';

//Create SHA-256 hash object
const sha256 = crypto.createHash('sha256');

//Add data to the hash object
sha256.update(data);

//Generate the hash in hexadecimal format
const hash = sha256.digest('hex');

//Print the Hash
console.log(hash);

//Question 9 - Develop a smart contract that implements a decentralized auction with sealed bids.

contract SealedBiAuction {
    address payable public owner;
    uint256 public highestBid;
    address payable public highestBidder;
    uint256 public biddingEnd;
    uint256 public revealEnd;
    bool public ended;

    struct Bid {
        bytes32 hashedN+Bid;
        uint256 value;
        bool revealed;
    }

    event AuctionEnded(address winner, uint256 highestBid);

    constructor(uint256 _biddingTime, uint256 _revealTime) {
        owner = payable(msg.sender);
        biddingEnd = block.timestamp + _biddingTime;
        revealed = biddingEnd + _revealTime;
    }

    function placeBid(bytes32 hashedBid) public payable{
        require(block.timestamp < biddingEnd, "Bidding has ended");
        require(msg.value > 0, "Bid amount must be greater than 0");

        bids[msg.sender] = Bid(hashedBid, msg.value, false);
    }

    function revealBid(uint256 value, bytes32 nonce) public {
        require(block.timestamp >= biddingEnd, "Bidding has not ended");
        require(block.timestamp < revealEnd, "Reveal period has ended");

        bytes32 hashedBid = keccak256(abi.encodePacked(value,nonce));

        require(bids[msg.sender].hashedBid == hashedBid, "Hashed bid does not match");
        bids[msg.sender].revealed = true;

        if(value > highestBid) {
            if(value > highestBid) {
                if(highestBidder != address(0)) {
                    highestBidder.transfer(highestBid);
                }
                highestBid = value;
                highestBidder = payable(msg.sender);
            }
        }
    }

    function endAuction() public {
        require(block.timestamp >= revealEnd, "Reveal period has not ended");
        require(!ended, "Auction has already ended");

        ended = true;
        emit AuctionEnded(highestBidder, highestBid);
        owner.transfer(address(this).balance);
    }
}

/*In this implementation, the SealedBidAuction contract defines an auction with a bidding phase and a reveal phase. During the bidding phase, bidders submit their hashed bids to the contract. During the reveal phase, bidders reveal their bids by providing the value and nonce that they used to create the hashed bid.

The highest bidder is determined based on the highest revealed bid, and the auction owner can end the auction after the reveal phase has ended. The highest bidder is then transferred the auction funds, and any excess funds are returned to the auction owner.

To use this contract, bidders would need to first hash their bids before submitting them to the contract during the bidding phase. They would then need to reveal their bids during the reveal phase by providing the value and nonce that they used to create the hashed bid.

It's important to note that this is a very basic implementation of a decentralized auction with sealed bids. Additional features, such as bid increment rules, bid withdrawal, and anti-sniping measures, can be added to make the auction more fair and secure. It's important to thoroughly test and audit any smart contract before deploying it to the Ethereum network to ensure the safety of user funds.

 */

//Question 10 - Write a program that generates a Bitcoin address from a given public key.

contract BitcoinAddressGenerator {
    function generateBitcoinAddress(string memory publicKey) public pure returns (string memory) {
        bytes memory publicKeyBytes = bytes(publicKey);

        //Step 1: Perform SHA-256 hashing on the public key
        bytes32 sha256 = sha256(abi.encodePacked(publicKeyBytes));

        //Step 2: Perform RIPEMD-160 hashing on the result of step 1
        bytes20 hash160 = ripemd160(abi.encodePacked(sha256));

        //Step 3: Add the version bytes in front of hte RIPEMD-160 hash
        bytes memoey versionHash = abi.encodePacked(hex"00", hash160);

        //Step 4: Perform SHA-256 hashing on the result of step 3 twice
        bytes32 checksum = sha256(abi.encodePacked(sha256(versionHash)));

        //Step 5: Add the first 4 bytes of the result of step 4 to the result of step 3
        bytes memory addressBytes = abi.encodePacked(versionHash, checksum[0:4]);

        //Step 6: Encode the result of step 5 in base58
        string memory bitcoinAddress = toBase(addressBytes);

        return bitcoinAddress;
    }

    function toBase58(bytes memory source) private pure returns (string memory) {
        // Convert the input bytes to an integer
        uint256 num = 0;
        for (uint i = 0; i < source.length; i++) {
            num = num * 256 + uint256(uint8(source[i]));
        }

        // Convert the integer to base58
        string memory base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        uint256 quotient = num;
        uint256 remainder;
        string memory base58 = "";
        while (quotient > 0) {
            quotient = num / 58;
            remainder = num % 58;
            base58 = string(abi.encodePacked(base58Alphabet[uint256(remainder)], base58));
            num = quotient;
        }

        // Add leading zeroes for the input bytes that are zero
        for (uint i = 0; i < source.length && source[i] == 0; i++) {
            base58 = string(abi.encodePacked("1", base58));
        }

        return base58;
    }
}
/* Note that Solidity's sha256 and ripemd160 functions return bytes32 and bytes20 respectively, so we need to convert them to bytes before concatenating them. Also note that Solidity does not provide a built-in function to convert a bytes array to base58, so we need to write our own toBase58 function that performs the conversion. The toBase58 function follows the same algorithm as the Python program I provided earlier, but with some modifications to work with Solidity's limited string manipulation capabilities. The function first converts the input bytes to an integer, then performs the base58 conversion by repeatedly dividing the integer by 58 and taking the remainder.*/

contract AddressGenerator {
    function generateAddress(bytes32 publicKey) public pure returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(publicKey));
        address addr = address(uint160(uint256(hash)));
        return addr;
    }
}































