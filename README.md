# Transfer restriction with Self, a zero-knowledge identity protocol

Self is a **privacy-first, open-source identity protocol** that uses **zero-knowledge proofs** for secure identity verification.

It enables **Sybil resistance** and **selective disclosure** using real-world attestations like passports. 

[TOC]



## Introduction

### How it Works

Self Protocol  allows **digital identity verification** with **zero-knowledge proofs** in three steps:

1. **Scan its Passport:** the user scan its  passport using the NFC reader of its phone.
2. **Generate a Proof:** the Self application generates a zk proof over the user's passport, selecting only what the user wants to disclose.
3. **Share The Proof:** the user can now share its zk proof with the selected application.

### Use case: RWA Tokenization (stocks, equities, debt)

Self can be relevant to apply transfers restrictions on a token representing a financial instrument such as stock, equities or debt.

#### Key Disclosures to Restrict for Tokenized Shares

1. **Nationality**
   - **Why:** Different countries have regulations on who can hold shares (e.g., restrictions on foreign investors).
   - **Restriction Use:** Block or allow share ownership based on nationality.
2. **Age Check Result (older_than)**
   - **Why:** Legal minimum age requirements to own or trade shares (e.g., must be 18+).
   - **Restriction Use:** Prevent minors from holding or transacting tokenized shares.
3. **OFAC Checks (passport_no_ofac, name_and_dob_ofac, name_and_yob_ofac)**
   - **Why:** Must comply with sanctions and anti-money laundering (AML) regulations to avoid transferring shares to blacklisted or restricted individuals/entities.
   - **Restriction Use:** Block shares transfers or ownership if the user is on a sanctions or watchlist (OFAC).
4. **User ID / Application (contextual)**
   - **Why:** To ensure each tokenized share is linked to a verified identity and application scope, preventing double registration or fraud.
   - **Restriction Use:** Prevent double ownership

#### CMTAT and RuleEngine

- [CMTAT](https://github.com/CMTA/CMTAT/) is a security token framework that includes various compliance features such as conditional transfer, account freeze, and token pause. By the past, CMTAT has been used by several different companies such as Taurus SA, UBS (Project Guardian), obligate (on-chain bond and dividend) and many others.
- [RuleEngine](https://github.com/CMTA/RuleEngine/)  is an external contract used to apply transfer restrictions to another contract, initially the CMTAT. Acting as a controller, it can call different contract rules and apply these rules on each transfer.

### Goal of this project

The project aims to provide a rule called `RuleSelf` to allow an issuer to restrict transfers of a CMTAT token deployed by using some propreties of a passport.

Typically, it will be possible to forbid transfer to address present on OFAC sanction list.

During this hackaton, unfortunataly, only the Rule was deployed and no integration testing has been done with CMTAT and RuleEngine.



#### Schema

Schema showing the interaction between a token holder and a CMTAT token with a configured RuleEngine as well as a RuleSelf.

A same `RuleSelf`and `RuleEngine`can be used for several different tokens.

![self-CMTAT.drawio](../RuleSelf/doc/self-CMTAT.drawio.png)



- Schema showing the interaction between a Self user and the smart contract `RuleSelf`.





![self-ruleSelf.drawio](../RuleSelf/doc/self-ruleSelf.drawio.png)

## Details

### How Self Identity Verification Works

Self uses zero-knowledge proofs to verify identity document information without exposing the actual document data. Here's the complete flow:

#### 1. Frontend Setup ( Web App)

- **SelfAppBuilder** creates a configuration object defining wha the user wants to verify
- **SelfQRcodeWrapper** displays a QR code that users scan with the Self mobile app
- The QR code contains the  verification requirements and a unique session ID

#### 2. Mobile App Processing

- User scans QR code with Self mobile app
- App reads the identity document's NFC chip and generates a zero-knowledge proof
- Proof validates requirements (age, nationality, etc.) without revealing actual data
- Mobile app sends proof to  the smart contract via the Self relayer service
  - The smart contract entrypoint is the public function  `verifySelfProof`

#### 3. Smart contract verification

- The smart contract checks the proof validity inside the function `verfySelfProof`
- Then it calls the hub contract `identityVerificationHubV2`
- This contract will perform a callback to the the function `onVerificationSuccess`
- Then the smart contract can perform custom logic inside the customizable verification hook `customVerificationHook`

Reference: [https://docs.self.xyz/sdk-reference/selfappbuilder](https://docs.self.xyz/sdk-reference/selfappbuilder)

### Concepts

#### Disclosure

Disclosures allow the users to reveal information about  their passport. For example, if  an application (smart contract or backend server) want to check if a user is above the age of 18 then at the very least the application will end up disclosing the lower bound of the age range of the user.

#### List of Possible Disclosures

The `disclosures` object allows the application to specify what information the application wants to verify and request from the user's passport:

```json
disclosures: {
    // Identity fields (optional)
    issuing_state?: boolean,      // Country that issued the passport
    name?: boolean,               // Full name
    passport_number?: boolean,    // Passport number
    nationality?: boolean,        // Nationality
    date_of_birth?: boolean,      // Date of birth
    gender?: boolean,             // Gender
    expiry_date?: boolean,        // Passport expiry date
    
    // Verification requirements (optional)
    minimumAge?: number,          // Minimum age requirement (e.g., 18, 21)
    excludedCountries?: string[], //
    ofac?: boolean,               // Enable OFAC sanctions checking
}
```



1. **Issuing Country** – The country that issued the passport.
2. **Full Name** – The name as shown on the passport.
3. **Passport Number** – The user's passport number.
4. **Nationality** – The user's nationality according to the passport.
5. **Date of Birth** – Full date of birth.
6. **Gender** – Gender information from the passport.
7. **Passport Expiry Date** – When the passport will expire.
8. **Age Check Result** – Whether the user is older than a specific age (e.g., 18).
9. Countries excluded -  ISO 3-letter codes (e.g., ['IRN', 'PRK'])
10. **OFAC Check (Passport Number)** – Result of a sanctions list check using the passport number.
11. **OFAC Check (Name and DOB)** – Result of a sanctions list check using the name and full date of birth.
12. **OFAC Check (Name and YOB)** – Result of a sanctions list check using the name and year of birth.



For our use case, we have performed the following ferification:

- The token holder must be major (18 years old minimum)
- IRAN and PRK are excluded
- OFAC sanctions are checked

```json
disclosures: {
     minimumAge: 18,
     ofac: true,
     excludedCountries: [countries.IRAN, countries.AFGHANISTAN],
     expiry_date: true,
}
```



Reference: [https://docs.self.xyz/use-self/use-deeplinking](https://docs.self.xyz/use-self/use-deeplinking)

## Contracts

This section explains how the contracts are build



### Constructor

The constructor set the initial config identifiant and scope value.

It also sets the identity hub verification address.

```solidity
constructor(
        address identityVerificationHubAddress,
        bytes32 configId_,
        uint256 scopeValue
    ) SelfVerificationRoot(identityVerificationHubAddress, scopeValue) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setConfigId(configId_);
    }
```



### Configuration

    //App-specific configuration ID
    bytes32 public configId;

#### getConfigId

Override to provide configId for verification

```solidity
function getConfigId(
        bytes32 destinationChainId,
        bytes32 userIdentifier, 
        bytes memory userDefinedData // Custom data from the qr code configuration
    ) public view override returns (bytes32) {
        // Return your app's configuration ID
        return configId;
    }
```

#### Set config id

##### Code

```solidity
function setConfigId(bytes32 _configId) public onlyRole(DEFAULT_ADMIN_ROLE) {
	_setConfigId(_configId);
}

function _setConfigId(bytes32 _configId) internal {
	configId = _configId;
}
```

##### Compute its value

The [Self Configuration Tools](https://tools.self.xyz/)  allows to create  a verification configuration and generates a config ID. This tool allows you to configure age requirements, country restrictions, and OFAC checks with a user-friendly interface. A contract representing the configuration will be deployed by the tool

![AgeVerification](../RuleSelf/assets/AgeVerification.png)

![countries](../RuleSelf/assets/countries.png)



![OFAC](../RuleSelf/assets/OFAC.png)

![config-deployment](../RuleSelf/assets/config-deployment.png)

Reference:

- [tools.self.xyz](https://tools.self.xyz)

- [docs.self.xyz/contract-integration/basic-integration](https://docs.self.xyz/contract-integration/basic-integration)

### customVerificationHook

Override to handle successful verification.

This hook is  called if the proof is considered as valid.

It is responsible to register the user and to store the nullifier.

```solidity
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
```



### Scope

The scope is the final value you set in your Self Verification contract. It's generated by hashing the scope seed 🌱 with the address or DNS, creating a unique identifier for the verification requirements.

Your contract needs a proper scope for verification. You have two approaches:

Your contract needs a proper scope for verification. You have two approaches:

#### Option 1: Predict address with CREATE2 (advanced)

```
// Calculate scope before deployment using predicted address
// Use tools.self.xyz to calculate scope with your predicted contract address
```

Option 2: Update scope after deployment (easier)

```
uint256 public scope;

function setScope(uint256 _scope) external onlyOwner {
    scope = _scope;
    // Update the scope in the parent contract
    _setScope(_scope);
}
```

After deployment, use the [Self Configuration Tools](https://tools.self.xyz/) to calculate the actual scope with your deployed contract address and update it using the setter function.

![scope](../RuleSelf/assets/scope.png)

Once we have the scope, we set the value inside the smart contract

![smart-contract-set-scope](../RuleSelf/assets/smart-contract-set-scope.png)



See [https://tools.self.xyz](https://tools.self.xyz)



### Contract management

These functions allows to open and close the registration, as well as returned a boolean to indicate if a target address is registered inside the contract.

Taken from the [Aidrop contract example](https://github.com/selfxyz/self/blob/main/contracts/contracts/example/Airdrop.sol)

```solidity
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
     * @notice Checks if a given address is registered.
     * @param registeredAddress The address to check.
     * @return True if the address is registered, false otherwise.
     */
    function isRegistered(address registeredAddress) public view returns (bool) {
        return _registeredUserIdentifiers[uint256(uint160(registeredAddress))];
    }
```



## Limitation of the solution

- It may happen that some tokens can only be sold to citizens of a certain country, e.g. the country where the shares are issued. Self's solution does not allow for determining these restrictions based on residency but only on nationality.
- It is not possible for a token holder to transfer his tokens to another address because this other address will not be registered in the contracts. 

Possible solutions are as follows:

- A "recoveryWallet/burnAndMint" function accessible only to the issuer to perform the transfer

- Allow through a dedicated function a token holder to:
  - Delete their previous address
  - Add their new address through a function
- A malicious person could steal the passport of a person and use it to create a valid identifiant and to register inside the `RuleSelf`contract.





