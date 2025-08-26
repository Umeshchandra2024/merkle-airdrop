// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20,SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MerkleAirdrop is EIP712{
    using SafeERC20 for IERC20;
    // Purpose:
    // 1. Manage a list of addresses and corresponding token amounts eligible for the airdrop.
    // 2. Provide a mechanism for eligible users to claim their allocated tokens.

    //state variables
    bytes32 private immutable i_merkleRoot;
    IERC20 private immutable i_airdropToken;
    mapping(address claimer => bool claimed) private s_hasClaimed;
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("Claim(address account,uint256 amount)");

    struct AirdropClaim {
        address account;
        uint256 amount;
    }
    // events
    event Claim(address indexed account, uint256 amount);
    //errors
    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();
    error MerkleAirdrop__InvalidSignature();

    constructor(bytes32 merkleRoot, IERC20 airdropToken) EIP712("MerkleAirdrop", "1") {
        i_merkleRoot = merkleRoot;
        i_airdropToken = airdropToken;
    }

    function claim(address account, uint256 amount, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) external {
        // CEI pattern: Check, Effect, Interact
        // 1. Check if the account has already claimed
        // 2. If not, calculate the leaf node hash and verify the Merkle proof
        // 3. Mark the account as claimed
        // 4. Emit an event for the claim
        // 5. Transfer the tokens to the account
        if(s_hasClaimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed(); // Account has already claimed
        }
        // check the signatures
        if(!_isValidSignature(account, getMessageHash(account, amount), v, r, s)) {
            revert MerkleAirdrop__InvalidSignature(); // Invalid signature
        }
        // 1. Calculate the leaf node hash
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        // 2. Verify the Merkle Proof
        if(!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop__InvalidProof();
        }
        s_hasClaimed[account] = true; // Mark the account as claimed
        // 3. Emit event        
        emit Claim(account, amount);
        // 4. Transfer the tokens to the account
        i_airdropToken.safeTransfer(account, amount);  // safeTransfer ensures that the transfer is successful and reverts if it fails.
        
    }

    function getMessageHash(address account, uint256 amount) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, AirdropClaim({
            account: account,
            amount: amount
        }))));
    }
    
    // getter functions
    function getMerkleRoot() external view returns (bytes32) {
        return i_merkleRoot;
    }

    function getAirdropToken() external view returns (IERC20) {
        return i_airdropToken;
    }

    function _isValidSignature(address account, bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view returns (bool) {
        (address actualSigner, , ) = ECDSA.tryRecover(digest, v, r, s);
        return actualSigner == account; // Check if the recovered address matches the account
    }
}