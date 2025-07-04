// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;


// OpenZeppelin
import {MerkleProof} from "OZ/utils/cryptography/MerkleProof.sol";
import {AccessControl} from "OZ/access/AccessControl.sol";

// self
import {ISelfVerificationRoot} from "self/interfaces/ISelfVerificationRoot.sol";
import {CircuitAttributeHandlerV2} from "self/libraries/CircuitAttributeHandlerV2.sol";

import {SelfVerificationRoot} from "self/abstract/SelfVerificationRoot.sol";

/**
 * @title Airdrop V2 (Experimental)
 * @notice This contract manages a RuleEngine Transfer Rule by verifying user registrations with zero‐knowledge proofs
 *         supporting both E-Passport and EU ID Card attestations.
 *         It is provided for testing and demonstration purposes only.
 *         **WARNING:** This contract has not been audited and is NOT intended for production use.
 * @dev Inherits from SelfVerificationRoot V2 for registration logic and Access Control for administrative control.
 */
contract Airdrop is SelfVerificationRoot, Ownable {
    // ====================================================
    // Storage Variables
    // ====================================================

    /// @notice Indicates whether the registration phase is active.
    bool public isRegistrationOpen;

    /// @notice Maps nullifiers to user identifiers for registration tracking
    mapping(uint256 nullifier => uint256 userIdentifier) internal _nullifierToUserIdentifier;

    /// @notice Maps user identifiers to registration status
    mapping(uint256 userIdentifier => bool registered) internal _registeredUserIdentifiers;

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Reverts when an invalid Merkle proof is provided.
    error InvalidProof();

    /// @notice Reverts when an unregistered address attempts to claim tokens.
    error NotRegistered(address nonRegisteredAddress);

    /// @notice Reverts when registration is attempted while the registration phase is closed.
    error RegistrationNotOpen();

    /// @notice Reverts when a claim attempt is made while registration is still open.
    error RegistrationNotClosed();


    /// @notice Reverts when an invalid user identifier is provided.
    error InvalidUserIdentifier();

    /// @notice Reverts when a user identifier has already been registered
    error UserIdentifierAlreadyRegistered();

    /// @notice Reverts when a nullifier has already been registered
    error RegisteredNullifier();

    // ====================================================
    // Events
    // ====================================================

    /// @notice Emitted when a user successfully claims tokens.
    /// @param index The index of the claim in the Merkle tree.
    /// @param account The address that claimed tokens.
    /// @param amount The amount of tokens claimed.
    event Claimed(uint256 index, address account, uint256 amount);

    /// @notice Emitted when the registration phase is opened.
    event RegistrationOpen();

    /// @notice Emitted when the registration phase is closed.
    event RegistrationClose();


    /// @notice Emitted when a user identifier is registered.
    event UserIdentifierRegistered(uint256 indexed registeredUserIdentifier, uint256 indexed nullifier);

    // ====================================================
    // Constructor
    // ====================================================

    /**
     * @notice Constructor for the experimental Airdrop V2 contract.
     * @dev Initializes the airdrop parameters, zero-knowledge verification configuration,
     *      and sets the ERC20 token to be distributed. Supports both E-Passport and EUID attestations.
     * @param identityVerificationHubAddress The address of the Identity Verification Hub V2.
     * @param scopeValue The expected proof scope for user registration.
     * @param tokenAddress The address of the ERC20 token for airdrop.
     */
    constructor(
        address identityVerificationHubAddress,
        uint256 scopeValue,
        address tokenAddress
    ) SelfVerificationRoot(identityVerificationHubAddress, scopeValue) Ownable(_msgSender()) {
        token = IERC20(tokenAddress);
    }

    // ====================================================
    // public/Public Functions
    // ====================================================

    /**
     * @notice Updates the scope used for verification.
     * @dev Only callable by the contract owner.
     * @param newScope The new scope to set.
     */
    function setScope(uint256 newScope) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _setScope(newScope);
    }

    /**
     * @notice Opens the registration phase for users.
     * @dev Only callable by the contract owner.
     */
    function openRegistration() public onlyRole(DEFAULT_ADMIN_ROLE) {
        isRegistrationOpen = true;
        emit RegistrationOpen();
    }

    /**
     * @notice Closes the registration phase.
     * @dev Only callable by the contract owner.
     */
    function closeRegistration() public onlyRole(DEFAULT_ADMIN_ROLE) {
        isRegistrationOpen = false;
        emit RegistrationClose();
    }

    /**
     * @notice Retrieves the expected proof scope.
     * @return The scope value used for registration verification.
     */
    function getScope() public view returns (uint256) {
        return _scope;
    }

    /**
     * @notice Checks if a given address is registered.
     * @param registeredAddress The address to check.
     * @return True if the address is registered, false otherwise.
     */
    function isRegistered(address registeredAddress) public view returns (bool) {
        return _registeredUserIdentifiers[uint256(uint160(registeredAddress))];
    }

    /**
     * @notice Allows a registered user to claim their tokens.
     * @dev Reverts if registration is still open, if claiming is disabled, if already claimed,
     *      or if the sender is not registered. Also validates the claim using a Merkle proof.
     * @param index The index of the claim in the Merkle tree.
     * @param amount The amount of tokens to be claimed.
     * @param merkleProof The Merkle proof verifying the claim.
     */
   /* function claim(uint256 index, uint256 amount, bytes32[] memory merkleProof) public {
        if (isRegistrationOpen) {
            revert RegistrationNotClosed();
        }
        if (!isClaimOpen) {
            revert ClaimNotOpen();
        }
        if (claimed[msg.sender]) {
            revert AlreadyClaimed();
        }
        if (!_registeredUserIdentifiers[uint256(uint160(msg.sender))]) {
            revert NotRegistered(msg.sender);
        }

        // Verify the Merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, msg.sender, amount));
        if (!MerkleProof.verify(merkleProof, merkleRoot, node)) revert InvalidProof();

        // Mark as claimed and transfer tokens.
        _setClaimed();
        token.safeTransfer(msg.sender, amount);

        emit Claimed(index, msg.sender, amount);
    }*/

    // ====================================================
    // Override Functions from SelfVerificationRoot
    // ====================================================

    /**
     * @notice Hook called after successful verification - handles user registration
     * @dev Validates registration conditions and registers the user for both E-Passport and EUID attestations
     * @param output The verification output containing user data
     */
    function customVerificationHook(
        ISelfVerificationRoot.GenericDiscloseOutputV2 memory output,
        bytes memory /* userData */
    ) internal override {
        // Check if registration is open
        if (!isRegistrationOpen) {
            revert RegistrationNotOpen();
        }

        // Check if nullifier has already been registered
        if (_nullifierToUserIdentifier[output.nullifier] != 0) {
            revert RegisteredNullifier();
        }

        // Check if user identifier is valid
        if (output.userIdentifier == 0) {
            revert InvalidUserIdentifier();
        }

        // Check if user identifier has already been registered
        if (_registeredUserIdentifiers[output.userIdentifier]) {
            revert UserIdentifierAlreadyRegistered();
        }

        _nullifierToUserIdentifier[output.nullifier] = output.userIdentifier;
        _registeredUserIdentifiers[output.userIdentifier] = true;

        // Emit registration event
        emit UserIdentifierRegistered(output.userIdentifier, output.nullifier);
    }

    // ====================================================
    // Internal Functions
    // ====================================================

    /**
     * @notice Internal function to mark the caller as having claimed their tokens.
     * @dev Updates the claimed mapping.
     */
    function _setClaimed() internal {
        claimed[msg.sender] = true;
    }
}