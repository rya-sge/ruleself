// SPDX-License-Identifier: MPL-2.0

pragma solidity ^0.8.20;

import "OZ/access/AccessControl.sol";
import "../../modules/RuleEngineValidationCommon.sol";
import "../../modules/MetaTxModuleStandalone.sol";
import "./abstract/RuleAddressList/RuleAddressList.sol";
import "./abstract/RuleWhitelistCommon.sol";

/**
 * @title Wrapper to call several different whitelist rules
 */
contract RuleWhitelistWrapper is
    RuleEngineValidationCommon,
    MetaTxModuleStandalone,
    RuleWhitelistCommon
{
    /**
     * @param admin Address of the contract (Access Control)
     * @param forwarderIrrevocable Address of the forwarder, required for the gasless support
     */
    constructor(
        address admin,
        address forwarderIrrevocable
    ) MetaTxModuleStandalone(forwarderIrrevocable) {
        if (admin == address(0)) {
            revert RuleEngine_AdminWithAddressZeroNotAllowed();
        }
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * @notice Go through all the whitelist rules to know if a restriction exists on the transfer
     * @param _from the origin address
     * @param _to the destination address
     * @return The restricion code or REJECTED_CODE_BASE.TRANSFER_OK
     **/
    function detectTransferRestriction(
        address _from,
        address _to,
        uint256 /*_amount*/
    ) public view override returns (uint8) {
        address[] memory targetAddress = new address[](2);
        bool[] memory isListed = new bool[](2);
        bool[] memory result = new bool[](2);
        targetAddress[0] = _from;
        targetAddress[1] = _to;
        uint256 rulesLength = _rulesValidation.length;
        // For each whitelist rule, we ask if from or to are in the whitelist
        for (uint256 i = 0; i < rulesLength; ++i) {
            // External call
            isListed = RuleAddressList(_rulesValidation[i])
                .addressIsListedBatch(targetAddress);
            if (isListed[0] && !result[0]) {
                // Update if from is in the list
                result[0] = true;
            }
            if (isListed[1] && !result[1]) {
                // Update if to is in the list
                result[1] = true;
            }
            if (result[0] && result[1]) {
                break;
            }
        }
        if (!result[0]) {
            return CODE_ADDRESS_FROM_NOT_WHITELISTED;
        } else if (!result[1]) {
            return CODE_ADDRESS_TO_NOT_WHITELISTED;
        } else {
            return uint8(REJECTED_CODE_BASE.TRANSFER_OK);
        }
    }

    function detectTransferRestrictionFrom(
        address spender,
        address _from,
        address _to,
        uint256 /*_amount*/
    ) public view override returns (uint8) {
        address[] memory targetAddress = new address[](3);
        bool[] memory isListed = new bool[](3);
        bool[] memory result = new bool[](3);
        targetAddress[0] = _from;
        targetAddress[1] = _to;
        targetAddress[2] = spender;
        uint256 rulesLength = _rulesValidation.length;
        // For each whitelist rule, we ask if from or to are in the whitelist
        for (uint256 i = 0; i < rulesLength; ++i) {
            // External call
            isListed = RuleAddressList(_rulesValidation[i])
                .addressIsListedBatch(targetAddress);
            if (isListed[0] && !result[0]) {
                // Update if from is in the list
                result[0] = true;
            }
            if (isListed[1] && !result[1]) {
                // Update if to is in the list
                result[1] = true;
            }
            if (isListed[2] && !result[2]) {
                // Update if spender is in the list
                result[2] = true;
            }
            if (result[0] && result[1] && result[2]) {
                break;
            }
        }
        if (!result[0]) {
            return CODE_ADDRESS_FROM_NOT_WHITELISTED;
        } else if (!result[1]) {
            return CODE_ADDRESS_TO_NOT_WHITELISTED;
        } else if (!result[2]) {
            return CODE_ADDRESS_SPENDER_NOT_WHITELISTED;
        } else {
            return uint8(REJECTED_CODE_BASE.TRANSFER_OK);
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

    /*//////////////////////////////////////////////////////////////
                           ERC-2771
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev This surcharge is not necessary if you do not use the MetaTxModule
     */
    function _msgSender()
        internal
        view
        override(ERC2771Context, Context)
        returns (address sender)
    {
        return ERC2771Context._msgSender();
    }

    /**
     * @dev This surcharge is not necessary if you do not use the MetaTxModule
     */
    function _msgData()
        internal
        view
        override(ERC2771Context, Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }

    /**
     * @dev This surcharge is not necessary if you do not use the MetaTxModule
     */
    function _contextSuffixLength()
        internal
        view
        override(ERC2771Context, Context)
        returns (uint256)
    {
        return ERC2771Context._contextSuffixLength();
    }
}
