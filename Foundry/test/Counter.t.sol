// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ruleSelf.sol";
import "../src/ruleSelfToken.sol";
import "../src/Registry.sol"; // if applicable

contract ruleSelfTest is Test {
    ruleSelf public ruleSelf;
    ruleSelfToken public token;
    Registry public registry;

    address owner = address(0xABCD);
    address user1 = address(0xBEEF);
    bytes32 scopeHash;

    uint256 nullifier;
    uint256 commitment;
    uint256[] attestationIds;

    function setUp() public {
        vm.startPrank(owner);

        // Deploy mock registry and other dependencies if needed
        registry = new Registry();

        // Deploy ruleSelf
        attestationIds.push(uint256(1)); // Simulating ATTESTATION_ID.E_PASSPORT

        scopeHash = keccak256(abi.encodePacked("https://test.com", "test-scope"));

        ruleSelf = new RuleSelf(
            address(registry), // Replace with `hub` if needed
            scopeHash,
            0, // version
            attestationIds,
            address(token)
        );

        // Setup verification config
        uint256[4] memory packedCountries = [
            uint256(0x414141), // AAA
            uint256(0x414243), // ABC
            uint256(0x434241), // CBA
            0
        ];

        VerificationConfigV1 memory config = VerificationConfigV1({
            olderThanEnabled: true,
            olderThan: 20,
            forbiddenCountriesEnabled: true,
            forbiddenCountriesListPacked: packedCountries,
            ofacEnabled: [true, true, true]
        });

        ruleSelf.setVerificationConfig(config);

        vm.stopPrank();
    }

    function testOpenRegistrationByOwner() public {
        vm.prank(owner);
        ruleSelf.openRegistration();

        bool open = ruleSelf.isRegistrationOpen();
        assertTrue(open, "Registration should be open");
    }
}
