// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;


// OpenZeppelin
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

// self
import {SelfVerificationRoot} from "@selfxyz/contracts/contracts/abstract/SelfVerificationRoot.sol";
import {ISelfVerificationRoot} from "@selfxyz/contracts/contracts/interfaces/ISelfVerificationRoot.sol";
import {IIdentityVerificationHubV2} from "@selfxyz/contracts/contracts/interfaces/IIdentityVerificationHubV2.sol";
import {SelfStructs} from "@selfxyz/contracts/contracts/libraries/SelfStructs.sol";
import {AttestationId} from "@selfxyz/contracts/contracts/constants/AttestationId.sol";
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

    /// @notice Emitted when the registration phase is opened.
    event RegistrationOpen();

    /// @notice Emitted when the registration phase is closed.
    event RegistrationClose();


    /// @notice Emitted when a user identifier is registered.
    event UserIdentifierRegistered(uint256 indexed registeredUserIdentifier, uint256 indexed nullifier);



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

    // ====================================================
    // Internal Functions
    // ====================================================

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

    /*function changeUserIdentifierAddress(address newIdentifier) {
        if (!_registeredUserIdentifiers[uint256(uint160(msg.sender))]) {
            revert NotRegistered(msg.sender);
        } else {
            _registeredUserIdentifiers = uint256(uint160(msg.sender))
        }
    }*/


}