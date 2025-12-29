# FrontRunner-Report   

## 1. Broken Factory Upgrade Mechanism
Severity: Critical 
Location: MiniSafeFactoryUpgradeable.sol

### Description
The MiniSafeFactoryUpgradeable contract includes functions intended to upgrade deployed instances of the protocol (upgradeSpecificContract and batchUpgradeContracts). However, these functions are fundamentally broken and will always revert due to incorrect access control assumptions and logic errors. The factory deploys MiniSafe proxies and immediately initializes them with a TimelockController as the owner.

```
solidity
// In deployUpgradeableMiniSafe
addresses.miniSafe = _deployMiniSafe(..., addresses.timelock);


// In MiniSafeAaveUpgradeable.initialize
__Ownable_init(_initialOwner); // _initialOwner is the Timelock
```

The UUPS upgrade mechanism (upgradeTo) is protected by onlyOwner. When the factory calls `contractAddress.upgradeTo(...)`, the msg.sender is the Factory, not the Timelock. Consequently, the proxy rejects the call.

The upgradeSpecificContract function attempts to verify the target contract using isMiniSafeContract.

```solidity
function isMiniSafeContract(address contractAddress) external view returns (bool) {
    if (contractAddress == miniSafeImplementation || ...) { return true; }
    return false;
}
```

This function compares the Proxy address (passed as input) with the stored Implementation addresses. Since a proxy address is never equal to its implementation address, this check always returns false, causing the transaction to revert even before the ownership check.

### Impact
The "Emergency Upgrade" functionality exposed by the factory is completely non-functional. Protocol administrators relying on this mechanism to fix bugs in deployed contracts will find themselves unable to execute upgrades, potentially leaving funds at risk during an actual emergency.

### Recommendation
Remove the upgradeSpecificContract, batchUpgradeContracts, and associated helper functions from the factory.

## 2. Malicious Upgrade via Insufficient Timelock Delay
**Severity: Critical** 
**Location: MiniSafeFactoryUpgradeable.sol**

 
Severity: Critical Location: MiniSafeFactoryUpgradeable.sol

### Description
The `MiniSafeFactoryUpgradeable` contract allows the deployment of MiniSafe instances with a TimelockController configuration that is insecure. Specifically, the `_validateConfig` function and other deployment helper functions allow a minDelay as short as 1 minute.

While the factory enforces the use of a Timelock, a 1-minute delay provides no meaningful security window for users. A malicious actor can:

Deploy a MiniSafe instance using `deployWithRecommendedMultiSig` (or any of the deployment functions), setting themselves as the sole proposer/executor and setting minDelay to 1 minute.
Wait for users to deposit funds into what appears to be a valid, factory-deployed contract.
Propose a malicious upgrade (e.g., to an implementation that allows draining funds) via the Timelock.
Wait 1 minute.
Execute the upgrade and drain the funds.
Because the delay is so short, users—who are restricted by the MiniSafe withdrawal windows (days 28-30)—have no time to react. Even the breakTimelock function (which allows emergency exit with a penalty) is ineffective because the attack can be executed faster than human reaction time.

### Impact
Users relying on the factory's reputation or the existence of a "Timelock" are susceptible to a complete loss of funds via a "Rug Pull" upgrade. The factory fails to enforce parameters that align with the protocol's security model.

### Recommendation
1. The factory must enforce a minimum delay that provides a sufficient reaction window for users. A minimum of 2 days is recommended to align with the `EMERGENCY_TIMELOCK` constant defined in the `MiniSafeAaveUpgradeable` contract. This ensures that if a malicious upgrade is proposed, users have 48 hours to notice and exit the protocol using breakTimelock.

The following changes update the validation logic in MiniSafeFactoryUpgradeable.sol to enforce a minimum delay of 2 days across all deployment functions.
Remove this line from all deployment entry functions `if (!(minDelay >= 1 minutes && minDelay <= 7 days)) revert();`

    ```solidity
    function _validateConfig(UpgradeableConfig memory config) internal pure {
        if (config.proposers.length == 0) revert();
        if (!(config.minDelay >= 2 days && config.minDelay <= 14 days)) revert();
        // Validate proposer addresses
        for (uint256 i = 0; i < config.proposers.length; i++) {
            if (config.proposers[i] == address(0)) revert();
        }

        // Validate delay configuration
        if (!(minDelay >= 2 days && minDelay <= 14 days)) revert();

        // Create dynamic arrays from fixed array
        address[] memory proposers = new address[](5);
        address aaveProvider
    ) external returns (MiniSafeAddresses memory addresses) {
        if (owner == address(0)) revert();
        if (!(minDelay >= 2 days && minDelay <= 14 days)) revert();

        address[] memory proposers = new address[](1);
        address[] memory executors = new address[](1);
    }
```


2. Protocol can enforce that the proposer's address must be a single multisig address which has a minimum of 5 signers so that any call made to the timelock contract via the multisig (which is the proposer and canceller) would be signed by atleast 4 signers to initiate an upgrade or to cancel an upgrade as well.
