// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;



/**
 * @title Airdrop V2 (Experimental)
 * @notice This contract manages a RuleEngine Transfer Rule by verifying user registrations with zero‐knowledge proofs
 *         supporting both E-Passport and EU ID Card attestations.
 *         It is provided for testing and demonstration purposes only.
 *         **WARNING:** This contract has not been audited and is NOT intended for production use.
 * @dev Inherits from SelfVerificationRoot V2 for registration logic and Access Control for administrative control.
 */
contract Airdrop is SelfVerificationRoot, Ownable {
       /* ============ Role ============ */
    bytes32 public constant SANCTIONLIST_ROLE = keccak256("SANCTIONLIST_ROLE");

    /* ============ String message ============ */
    string constant TEXT_ADDRESS_FROM_IS_SANCTIONED =
        "The sender is not registered";
    string constant TEXT_ADDRESS_TO_IS_SANCTIONED =
        "The recipient is notregistered";

    /* ============ Code ============ */
    // It is very important that each rule uses an unique code
    uint8 public constant CODE_ADDRESS_FROM_IS_NOT_REGISTERED = 61;
    uint8 public constant CODE_ADDRESS_TO_IS_NOT_REGISTERED = 62;

    // ====================================================
    // Constructor
    // ====================================================
    /**
     * @notice Constructor for the experimental Airdrop V2 contract.
     * @dev Initializes the airdrop parameters, zero-knowledge verification configuration,
     *      and sets the ERC20 token to be distributed. Supports both E-Passport and EUID attestations.
     * @param identityVerificationHubAddress The address of the Identity Verification Hub V2.
     * @param scopeValue The expected proof scope for user registration.
     */
    constructor(
        address identityVerificationHubAddress,
        uint256 scopeValue
    ) SelfVerificationRoot(identityVerificationHubAddress, scopeValue) Ownable(_msgSender()) {
       
    }
    

    /**
     * @notice Check if an addres is in the whitelist or not
     * @param _from the origin address
     * @param _to the destination address
     * @return The restricion code or REJECTED_CODE_BASE.TRANSFER_OK
     **/
    function detectTransferRestriction(
        address _from,
        address _to,
        uint256 /*_amount */
    ) public view override returns (uint8) {
         if (!_registeredUserIdentifiers[uint256(uint160(msg.sender))]) {
           return uint8(REJECTED_CODE_BASE.TRANSFER_OK);
        }
        return uint8(REJECTED_CODE_BASE.TRANSFER_OK);
    }


    function detectTransferRestrictionFrom(
        address spender,
        address _from,
        address _to,
        uint256 _amount
    ) public view override returns (uint8) {
        if(address(sanctionsList) != address(0)){
            if (sanctionsList.isSanctioned(spender)) {
                return CODE_ADDRESS_SPENDER_IS_SANCTIONED;
            } else {
                return detectTransferRestriction(_from,_to,_amount);
            }
        }
        return uint8(REJECTED_CODE_BASE.TRANSFER_OK);
    }

    /**
     * @notice To know if the restriction code is valid for this rule or not.
     * @param _restrictionCode The target restriction code
     * @return true if the restriction code is known, false otherwise
     **/
    function canReturnTransferRestrictionCode(
        uint8 _restrictionCode
    ) external pure override returns (bool) {
        return
            _restrictionCode == CODE_ADDRESS_FROM_IS_SANCTIONED ||
            _restrictionCode == CODE_ADDRESS_TO_IS_SANCTIONED||
            _restrictionCode == CODE_ADDRESS_SPENDER_IS_SANCTIONED;
    }

    /**
     * @notice Return the corresponding message
     * @param _restrictionCode The target restriction code
     * @return true if the transfer is valid, false otherwise
     **/
    function messageForTransferRestriction(
        uint8 _restrictionCode
    ) external pure override returns (string memory) {
        if (_restrictionCode == CODE_ADDRESS_FROM_IS_SANCTIONED) {
            return TEXT_ADDRESS_FROM_IS_SANCTIONED;
        } else if (_restrictionCode == CODE_ADDRESS_TO_IS_SANCTIONED) {
            return TEXT_ADDRESS_TO_IS_SANCTIONED;
        } else if (_restrictionCode == CODE_ADDRESS_SPENDER_IS_SANCTIONED) {
            return TEXT_ADDRESS_SPENDER_IS_SANCTIONED;
        } else {
            return TEXT_CODE_NOT_FOUND;
        }
    }

    /* ============ ACCESS CONTROL ============ */
    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        bytes32 role,
        address account
    ) public view virtual override(AccessControl) returns (bool) {
        // The Default Admin has all roles
        if (AccessControl.hasRole(DEFAULT_ADMIN_ROLE, account)) {
            return true;
        }
        return AccessControl.hasRole(role, account);
    }
}