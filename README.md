
## [H-1] Broken Factory Upgrade Mechanism

**Severity:** Critical
**Location:** MiniSafeFactoryUpgradeable.sol

### Description

The MiniSafeFactoryUpgradeable contract includes functions intended to upgrade deployed instances of the protocol (upgradeSpecificContract and batchUpgradeContracts). However, these functions are fundamentally broken and will always revert due to incorrect access control assumptions and logic errors. The factory deploys MiniSafe proxies and immediately initializes them with a TimelockController as the owner.

```solidity
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

---

## [H-2] Malicious Upgrade via Insufficient Timelock Delay

**Severity:** Critical
**Location:** MiniSafeFactoryUpgradeable.sol

### Description

The MiniSafeFactoryUpgradeable contract allows the deployment of MiniSafe instances with a TimelockController configuration that is insecure. Specifically, the _validateConfig function and other deployment helper functions allow a minDelay as short as 1 minute.

While the factory enforces the use of a Timelock, a 1-minute delay provides no meaningful security window for users. A malicious actor can:

* Deploy a MiniSafe instance using deployWithRecommendedMultiSig (or any of the deployment functions), setting themselves as the sole proposer/executor and setting minDelay to 1 minute.
* Wait for users to deposit funds into what appears to be a valid, factory-deployed contract.
* Propose a malicious upgrade (e.g., to an implementation that allows draining funds) via the Timelock. Wait 1 minute.
* Execute the upgrade and drain the funds.

Because the delay is so short, users—who are restricted by the MiniSafe withdrawal windows (days 28–30)—have no time to react. Even the breakTimelock function (which allows emergency exit with a penalty) is ineffective because the attack can be executed faster than human reaction time.

### Impact

Users relying on the factory's reputation or the existence of a "Timelock" are susceptible to a complete loss of funds via a "Rug Pull" upgrade. The factory fails to enforce parameters that align with the protocol's security model.

### Proof Of Concept

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

The factory must enforce a minimum delay that provides a sufficient reaction window for users. A minimum of 2 days is recommended to align with the EMERGENCY_TIMELOCK constant defined in the MiniSafeAaveUpgradeable contract.

The following changes update the validation logic in MiniSafeFactoryUpgradeable.sol to enforce a minimum delay of 2 days across all deployment functions.

Remove this line from all deployment entry functions:

```solidity
if (!(minDelay >= 1 minutes && minDelay <= 7 days)) revert();
```

```solidity
function _validateConfig(UpgradeableConfig memory config) internal pure {
    if (config.proposers.length == 0) revert();
    if (!(config.minDelay >= 2 days && config.minDelay <= 14 days)) revert();
    for (uint256 i = 0; i < config.proposers.length; i++) {
        if (config.proposers[i] == address(0)) revert();
    }
}
```

Protocol can enforce that the proposer's address must be a single multisig address with a minimum of 5 signers.

---

## [H-3] Payout Order Corruption via Swap-and-Pop

**Severity:** High
**Location:** MiniSafeAaveUpgradeable.sol → _removeMemberFromGroup

### Description

The _removeMemberFromGroup function handles the removal of a user from a thrift group. To remove the user from the payoutOrder array, it uses the "swap-and-pop" algorithm:

```solidity
group.payoutOrder[i] = group.payoutOrder[group.payoutOrder.length - 1];
group.payoutOrder.pop();
```

This method is gas-efficient (O(1)) but does not preserve the order of the array.

### Impact

In a ROSCA system, payout order determines economic value. When a member leaves, the last member jumps forward in line, violating fairness and allowing queue jumping.

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

### Recommendation

Replace swap-and-pop with ordered removal so that all elements after the removed index are shifted left, preserving order.

---

## [H-4] Payout Order Corruption via Array Duplication

**Severity:** High
**Location:** MiniSafeAaveUpgradeable.sol → _setupPayoutOrder

### Description

Admins can manually set payout order via setPayoutOrder. When the group becomes full, _setupPayoutOrder is automatically called and blindly appends all members again without checking whether payoutOrder is already populated.

### Impact

* Duplicate addresses in payoutOrder
* Broken cycle logic
* Double payouts or skipped members
* Corrupted group state

### Recommendation

```solidity
function _setupPayoutOrder(uint256 groupId) internal {
    ThriftGroup storage group = thriftGroups[groupId];
    
    if (group.payoutOrder.length == 0) {
        for (uint256 i = 0; i < group.members.length; i++) {
            group.payoutOrder.push(group.members[i]);
        }
    } else {
        for (uint256 i = group.payoutOrder.length; i < group.members.length; i++) {
            group.payoutOrder.push(group.members[i]);
        }
    }

    emit PayoutOrderSet(groupId, group.payoutOrder);
}
```


## [H-5] Emergency Withdrawal Fails to Transfer Recovered Tokens

### Description:
The `executeEmergencyWithdrawal` function in `MiniSafeAaveUpgradeable.sol` is designed to allow the contract owner to recover all funds from Aave in emergency situations. However, the function withdraws tokens from Aave to the contract itself (`address(this)`) but never transfers these tokens to the owner or distributes them to users. The withdrawn tokens become permanently trapped in the contract with no mechanism to retrieve them.

The function performs the withdrawal from Aave correctly but is missing the final step of transferring the recovered tokens. After withdrawFromAave completes:

- Tokens are sitting in the `MiniSafeAaveUpgradeable` contract  
- No transfer or safeTransfer call is made  
- No mechanism exists elsewhere in the contract to retrieve these tokens  
- The amountWithdrawn return value is captured but never used  

### Impact
Any tokens recovered through emergency withdrawal are permanently locked in the contract.  
The entire purpose of the emergency withdrawal mechanism is defeated.  
All user deposits that are emergency-withdrawn become inaccessible to both users and the protocol.

### Recommendation 
Transfer withdrawn tokens directly to the owner.

---

## [H-2] No Mechanism to Claim Aave External Reward Incentives

### Description:
Aave V3 implements an incentives system through the `RewardsController` contract that distributes additional token rewards to users who supply or borrow assets. These rewards are separate from the interest yield (`aToken` rebasing) and include tokens such as:

- `stkAAVE` (`Staked AAVE`) - Primary Aave incentive token  
- OP tokens on Optimism  
- ARB tokens on Arbitrum  
- MATIC on Polygon  
- Various partner tokens through co-incentive programs  

When `MiniSafe` deposits user funds to Aave, these incentive rewards accrue to the MiniSafeAaveIntegrationUpgradeable contract address. However, the protocol has no function to claim these rewards, resulting in permanent loss of all accumulated incentives.

This is distinct from the yield/interest issue because:

- Incentive rewards must be actively claimed via `RewardsController.claimRewards()`  
- Without a claim function, rewards accumulate but are never collected  

### Impact
Complete Loss of Incentive Rewards

### Recommendation
Add Rewards Claiming


## [H-3] Depositors Receive Zero Interest

### Description:
The MiniSafe protocol integrates with Aave V3 to generate yield on user deposits. However, due to a fundamental flaw in the share-based accounting system, users receive zero interest on their deposits. The protocol records shares equal to the exact deposit amount `(1:1 ratio)` and never updates this ratio as interest accrues. When users withdraw, they can only withdraw their original deposit amount, while all accumulated interest remains permanently trapped in the protocol with no mechanism for distribution.

This completely defeats the core value proposition of the protocol - earning yield on savings through Aave integration.

### Impact
Depositors get zero interest

**Recommendation**  
Add Exchange Rate Tracking to TokenStorage, or depositors should receive aToken after deposits

## [H-4] Incorrect Refund Calculation Due to totalContributed Not Being Reset at Cycle End

### Description:
In the MiniSafe thrift group functionality, when a cycle completes and payouts are processed, the `_resetCycle` function resets the contributions mapping (current cycle contributions) and `hasPaidThisCycle` flag, but fails to reset the `totalContributed` mapping. This creates a critical accounting discrepancy because `totalContributed` accumulates across all cycles, while the actual tokens from previous cycles have already been distributed as payouts.

When a user leaves a group via the `leaveGroup` function, the contract attempts to refund `group.totalContributed[msg.sender]`, which includes contributions from all previous cycles—tokens that no longer exist in the contract because they were already paid out to recipients.

This creates two severe issues:

- Excessive Refunds: Users who leave after multiple cycles could claim refunds far exceeding the actual tokens available  
- Fund Drain: The refund mechanism could drain tokens belonging to other users or from other groups  

### Impact
All Funds in the contract can be drained or wrongly refunded

### Recommendation
Reset totalContributed in `_resetCycle` 


## Medium Level Severity Issues

---

## [M-1] Excess Contribution Amounts Are Permanently Trapped in Contract

### Description: 
In the `MiniSafe` thrift group functionality, when users make contributions via the `makeContribution` function, they can send any amount greater than or equal to the required `contributionAmount`. The function only validates that the amount meets the minimum requirement but does not enforce an exact match or refund excess amounts.

Any tokens sent above the required contribution amount are permanently trapped in the contract with no mechanism for retrieval. The function transfers the full user-specified amount from the user's wallet but only tracks the standard `contributionAmount` in the group's accounting. When payouts are processed, they are calculated based on `contributionAmount` × `memberCount`, meaning the excess tokens are never distributed and remain stuck in the contract forever.

### Impact 
Excess contributions are permanently locked

### Recommendation  
Enforce Exact Contribution Amount.


## [M-2] Emergency Withdrawal Timelock Defeats Purpose of Emergency Response Mechanism

### Description: 
The `executeEmergencyWithdrawal` function in `MiniSafeAaveUpgradeable` implements a 2-day timelock before emergency withdrawals can be executed. While timelocks are generally good security practice for administrative functions, applying a timelock to an emergency function fundamentally contradicts its purpose.

In genuine emergency situations, such as protocol exploits, critical vulnerabilities, or external DeFi protocol failures, a 2-day delay renders the emergency mechanism completely ineffective.

By the time the timelock expires, the emergency that necessitated the withdrawal may have already resulted in complete loss of funds.

### Impact 
Emergency Scenarios Where 2-Day Delay Is Fatal

### Recommendation 
Remove Timelock

## [M-3] Thrift Group Contributions Held in Contract Instead of Earning Yield in Aave

### Description: 
The `MiniSafe` protocol integrates with Aave V3 to generate yield on user deposits through the personal savings functionality. However, when users make contributions to thrift groups via the `makeContribution` function, these funds are transferred directly to the `MiniSafeAaveUpgradeable` contract and held there idle instead of being deposited to Aave to earn yield.

This creates an architectural inconsistency where:

- Personal savings deposits → Sent to Aave → Earn yield  
- Thrift group contributions → Held in contract → Earn 0% yield  

Given that thrift groups operate on 30-day cycles and funds may sit in the contract for extended periods before payout, this represents a significant missed yield opportunity and contradicts the protocol's core value proposition of earning yield through Aave integration.

### Impact 
Contributions do not earn yields

### Recommendation
Deposit Contributions to Aave


## [M-4] Factory Contract Fails to Track Deployed Proxies - isMiniSafeContract Returns False for All Deployed Contracts

### Description:  
The `MiniSafeFactoryUpgradeable` contract contains a critical logic flaw in its `isMiniSafeContract` function. This function is designed to verify whether a given address is a legitimate MiniSafe contract deployed by the factory. However, it incorrectly checks if the address matches the implementation contract addresses rather than the deployed proxy addresses.

When the factory deploys the MiniSafe system, it creates `ERC1967` proxy contracts that point to the implementations. Users and administrators interact with these proxy addresses, not the implementations. However:

- The factory never stores the deployed proxy addresses  
- `isMiniSafeContract` only checks against implementation addresses  
- All deployed proxies return false when verified  
- Functions relying on this check (`upgradeSpecificContract`, `batchUpgradeContracts`) are completely broken  

This means the factory's upgrade functionality is non-operational, and any external systems relying on this verification will incorrectly reject legitimate MiniSafe contracts.

### Impact 
`isMiniSafeContract` always returns false  
`upgradeSpecificContract` always reverts  
`getContractImplementation` always returns zero address

### Recommendation
Add Proxy Tracking


### [M-5] cUSD Token Initialization Failure - Missing aToken Configuration and Broken Share Tracking

### Description:  
The MiniSafeTokenStorageUpgradeable contract is designed to manage supported tokens and their corresponding Aave `aToken` addresses. The contract hardcodes the `cUSD` (Celo Dollar) address and sets it as the default supported token during initialization. However, there are two critical flaws:

- Missing aToken Configuration: While cusdTokenAddress is set, the `tokenInfo[cusdTokenAddress]` struct is never initialized with the corresponding `aToken` address. This means `getTokenATokenAddress(cusdTokenAddress)` returns `address(0)`.  
- Broken Share Tracking: The `totalShares` for `cUSD` is never properly initialized in the tokenInfo mapping, causing all share-related operations to fail or produce incorrect results.  

These issues mean that `cUSD`—the primary stablecoin on Celo and the default token for the protocol—is completely non-functional. Any attempt to deposit, withdraw, or track balances for cUSD will fail or produce incorrect results.

### Recommendation 
Fix Initialize Function

---

## [M-6] nextPayoutDate Not Enforced - Payouts Can Be Processed Immediately Without Waiting for Scheduled Date

### Description: 
In the `MiniSafe` thrift group functionality, each group has a `nextPayoutDate` field that is intended to enforce a minimum waiting period between contribution collection and payout distribution. This date is set when the group is created and updated after each cycle. However, the `_checkAndProcessPayout` and `_processPayout` functions completely ignore this field, allowing payouts to be processed immediately once all members have contributed, regardless of the scheduled payout date.

This violates the expected behavior:

- Members contribute throughout a cycle period  
- At the end of the cycle (on nextPayoutDate), funds are distributed  
- The next cycle begins with a new contribution period  

Instead, the current implementation processes payouts instantly when the last member contributes, potentially within minutes of the cycle starting.

### Impact
Payouts occur immediately, not on scheduled date

### Recommendation  
Add Time Check in `_checkAndProcessPayout`


## Low Severity Issues

## [L-1] updatePoolDataProvider and updateAavePool Emit Identical Event - Impossible to Distinguish Configuration Changes

### Description:
In the `MiniSafeAaveIntegrationUpgradeable` contract, two distinct administrative functions—`updatePoolDataProvider` and `updateAavePool`—emit the same `AavePoolUpdated` event. This makes it impossible for off-chain systems, block explorers, indexers, and monitoring tools to distinguish between updates to the Pool Data Provider versus the Aave Pool contract.

Both contracts serve fundamentally different purposes in the Aave V3 architecture:

- IPool: Handles state-changing operations (`supply`, `withdraw`, `borrow`, `repay`)  
- IPoolDataProvider: Handles view-only queries (`getReserveTokensAddresses`, `getUserReserveData`)  

When an administrator updates either contract, the emitted event is identical, creating ambiguity in audit trails, monitoring systems, and incident response procedures.

### Impact
Cannot determine which contract was updated

### Recommendation
Add Separate Event for `PoolDataProvider`


## [L-2] Deposit Timestamp Is Overwritten and Never Used

### Description: 
Each new deposit overwrites the existing deposit timestamp, and the stored deposit time is never referenced or enforced anywhere in the protocol logic.

This results in a state variable that:

- Does not represent the original deposit time  
- Is not used for validation, accounting, lockups, cooldowns, or rewards  
- Can be arbitrarily refreshed by making a new deposit  

### Impact
Incorrect State Representation

### Recommendation
Enforce Deposit Time Properly


## [L-3] Misleading Error Message in Withdrawal Logic

**Severity:** Low
**Location:** MiniSafeAaveIntegrationUpgradeable.sol → withdrawFromAave

### Description

```solidity
require(amountWithdrawn > 0, "aToken address not found");
```

This message is incorrect. The aToken address is already verified earlier. This failure indicates a zero withdrawal, not a missing address.

### Recommendation

Update the revert message to accurately reflect the failure condition.
