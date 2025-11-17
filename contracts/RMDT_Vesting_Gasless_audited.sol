// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract RMDTVestingGasLess is Ownable, ERC2771Context, EIP712, ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error ZeroAddress();
    error InvalidParam();
    error NoSchedule();
    error NothingToClaim();
    error InsufficientFunds();
    error CapacityExceeded();
    error SignatureExpired();
    error InvalidSignature();
    error InvalidNonce();

    IERC20 public immutable token;
    uint16 public constant BPS_DENOM = 10_000;

    struct VestingSchedule {
        uint64 startTime;
        uint64 cliff;
        uint64 duration;
        uint16 tgeBps;
        uint256 totalAllocation;
        uint256 released;
        bool exists;
    }

    mapping(address => mapping(uint256 => VestingSchedule)) public schedules;
    mapping(address => uint256) public scheduleCount;
    uint256 public totalAllocated;
    // Tracks lifetime scheduled allocations (does not decrease on claims/cancellations)
    uint256 public totalEntitled;
    uint256 public immutable maxTotalAllocation;
    mapping(address => uint256) public nonces;

    event ScheduleCreated(
        address indexed beneficiary,
        uint256 indexed scheduleId,
        uint256 allocation,
        uint16 tgeBps,
        uint64 startTime,
        uint64 cliff,
        uint64 duration
    );
    event TokensClaimed(address indexed beneficiary, uint256 indexed scheduleId, uint256 amount);
    event ScheduleCancelled(address indexed beneficiary, uint256 indexed scheduleId, uint256 unvestedReturned);
    event Funded(address indexed from, uint256 amount);
    event WithdrawExcess(address indexed to, uint256 amount);
    event MetaClaimRelayed(
    address indexed relayer,      // who submitted the transaction on-chain
    address indexed user,         // actual end-user who signed the meta-tx
    address indexed beneficiary,
    uint256 scheduleId,
    uint256 amount
);
  event MetaClaimAllRelayed(
    address indexed relayer,      // who submitted the tx on-chain
    address indexed user,         // actual end-user who signed the meta-tx
    address indexed beneficiary,
    uint256 amount                // total amount claimed
);


    bytes32 private constant CLAIM_TYPEHASH = keccak256("Claim(address beneficiary,uint256 scheduleId,uint256 nonce,uint256 deadline)");
    bytes32 private constant CLAIMALL_TYPEHASH = keccak256("ClaimAll(address beneficiary,uint256 nonce,uint256 deadline)");
    
    // Admin role for timelock-controlled operations
    bytes32 public constant VESTING_MANAGER_ROLE = keccak256("VESTING_MANAGER_ROLE");
    // Role for instant schedule creation (managed by timelock governance)
    bytes32 public constant SCHEDULER_ROLE = keccak256("SCHEDULER_ROLE");

    constructor(
        IERC20 _token,
        address owner_,
        uint256 _maxTotalAllocation,
        address trustedForwarder
    ) Ownable(owner_) ERC2771Context(trustedForwarder) EIP712("RMDTVestingMulti", "1") {
        if (address(_token) == address(0)) revert ZeroAddress();
        if (owner_ == address(0)) revert ZeroAddress();
        if (_maxTotalAllocation == 0) revert InvalidParam();
        token = _token;
        maxTotalAllocation = _maxTotalAllocation;

        // Grant roles to the initial owner (timelock in production/testing)
        _grantRole(DEFAULT_ADMIN_ROLE, owner_);
        _grantRole(VESTING_MANAGER_ROLE, owner_);
    }

    function fund(uint256 amount) external onlyRole(VESTING_MANAGER_ROLE) {
        if (amount == 0) revert InvalidParam();
        token.safeTransferFrom(_msgSender(), address(this), amount);
        emit Funded(_msgSender(), amount);
    }

    function createSchedule(
        address beneficiary,
        uint256 allocation,
        uint16 tgeBps,
        uint64 startTime,
        uint64 cliff,
        uint64 duration
    ) external onlyRole(SCHEDULER_ROLE) {
        if (beneficiary == address(0)) revert ZeroAddress();
        if (allocation == 0 || tgeBps > BPS_DENOM || duration == 0) revert InvalidParam();

        // Enforce capacity against lifetime scheduled amount (strict cap that doesn’t shrink)
        uint256 newTotalEntitled = totalEntitled + allocation;
        if (newTotalEntitled > maxTotalAllocation) revert CapacityExceeded();

        // Also ensure sufficient funding for outstanding obligations (allocated but not yet claimed)
        uint256 newOutstanding = totalAllocated + allocation;
        uint256 currentBalance = token.balanceOf(address(this));
        if (currentBalance < newOutstanding) revert InsufficientFunds();

        uint256 scheduleId = scheduleCount[beneficiary];
        schedules[beneficiary][scheduleId] = VestingSchedule({
            startTime: startTime,
            cliff: cliff,
            duration: duration,
            tgeBps: tgeBps,
            totalAllocation: allocation,
            released: 0,
            exists: true
        });

        scheduleCount[beneficiary]++;
        // Update both trackers: lifetime scheduled and outstanding obligations
        totalEntitled = newTotalEntitled;
        totalAllocated = newOutstanding;

        emit ScheduleCreated(beneficiary, scheduleId, allocation, tgeBps, startTime, cliff, duration);
    }

    function _vestedAmount(VestingSchedule storage s) internal view returns (uint256) {
        uint256 start = uint256(s.startTime);
        if (block.timestamp < start) return 0;

        uint256 total = s.totalAllocation;
        uint256 tgeAmount = (total * uint256(s.tgeBps)) / BPS_DENOM;
        uint256 cliffPoint = start + uint256(s.cliff);

        if (block.timestamp < cliffPoint) return tgeAmount;

        uint256 timeFromCliff = block.timestamp - cliffPoint;
        uint256 dur = uint256(s.duration);
        if (timeFromCliff >= dur) return total;

        uint256 linearTotal = total - tgeAmount;
        uint256 linearVested = (linearTotal * timeFromCliff) / dur;
        return tgeAmount + linearVested;
    }

    /** 🔹 MODIFIED to subtract claimed amount from totalAllocated **/
    function _claimFor(address beneficiary, uint256 scheduleId) internal {
        VestingSchedule storage s = schedules[beneficiary][scheduleId];
        if (!s.exists) revert NoSchedule();

        uint256 vested = _vestedAmount(s);
        if (vested <= s.released) revert NothingToClaim();
        uint256 claimable = vested - s.released;

        s.released += claimable;
        totalAllocated -= claimable; // ✅ Decrease total allocated as per audit fix

        token.safeTransfer(beneficiary, claimable);

        emit TokensClaimed(beneficiary, scheduleId, claimable);

        if (s.released >= s.totalAllocation) {
            s.exists = false;
        }
    }

    function claim(uint256 scheduleId) external nonReentrant {
        address beneficiary = _msgSender();
        _claimFor(beneficiary, scheduleId);
    }

    /** 🔹 MODIFIED to subtract total claimed from totalAllocated **/
    function claimAll() external nonReentrant {
        address beneficiary = _msgSender();
        uint256 count = scheduleCount[beneficiary];
        if (count == 0) revert NoSchedule();

        uint256 totalToClaim = 0;
        for (uint256 i = 0; i < count; i++) {
            VestingSchedule storage s = schedules[beneficiary][i];
            if (!s.exists) continue;
            uint256 vested = _vestedAmount(s);
            if (vested <= s.released) continue;
            uint256 claimable = vested - s.released;
            s.released += claimable;
            totalToClaim += claimable;

            if (s.released >= s.totalAllocation) s.exists = false;

            emit TokensClaimed(beneficiary, i, claimable);
        }

        if (totalToClaim == 0) revert NothingToClaim();

        totalAllocated -= totalToClaim; // ✅ Adjust allocation tracking
        token.safeTransfer(beneficiary, totalToClaim);
    }

    /** 🔹 MODIFIED to keep accounting consistent **/
    function claimWithSignature(
        address beneficiary,
        uint256 scheduleId,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce != nonces[beneficiary]) revert InvalidNonce();

        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, beneficiary, scheduleId, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != beneficiary) revert InvalidSignature();

        nonces[beneficiary] = nonce + 1;

        uint256 beforeBal = token.balanceOf(address(this));
        _claimFor(beneficiary, scheduleId);
        uint256 afterBal = token.balanceOf(address(this));
        uint256 claimed = beforeBal - afterBal;

        emit MetaClaimRelayed(msg.sender,_msgSender(), beneficiary, scheduleId, claimed);
    }


    /**
     * @notice Trustless meta-tx to claim all schedules for beneficiary (relayer submits, contract verifies signature).
     */
    /** 🔹 MODIFIED to subtract total claimed **/
    function claimAllWithSignature(
        address beneficiary,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce != nonces[beneficiary]) revert InvalidNonce();

        bytes32 structHash = keccak256(abi.encode(CLAIMALL_TYPEHASH, beneficiary, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != beneficiary) revert InvalidSignature();

        nonces[beneficiary] = nonce + 1;

        uint256 count = scheduleCount[beneficiary];
        if (count == 0) revert NoSchedule();

        uint256 totalToClaim = 0;
        for (uint256 i = 0; i < count; i++) {
            VestingSchedule storage s = schedules[beneficiary][i];
            if (!s.exists) continue;
            uint256 vested = _vestedAmount(s);
            if (vested <= s.released) continue;
            uint256 claimable = vested - s.released;
            s.released += claimable;
            totalToClaim += claimable;
            if (s.released >= s.totalAllocation) s.exists = false;
            emit TokensClaimed(beneficiary, i, claimable);
        }

        if (totalToClaim == 0) revert NothingToClaim();

        totalAllocated -= totalToClaim; // ✅ Align accounting
        token.safeTransfer(beneficiary, totalToClaim);
        emit MetaClaimAllRelayed(msg.sender,_msgSender(), beneficiary, totalToClaim);
    }


/**
     * @notice Withdraw any tokens in this contract that exceed totalAllocated.
     */
    function withdrawExcess(address to) external onlyRole(VESTING_MANAGER_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();

    // Current token balance of the contract
    uint256 bal = token.balanceOf(address(this));

    
    if (bal <= totalAllocated) revert InsufficientFunds();

    uint256 withdrawable = bal - totalAllocated;
    token.safeTransfer(to, withdrawable);

    emit WithdrawExcess(to, withdrawable);
}


   function cancelSchedule(address beneficiary, uint256 scheduleId)
    external
    onlyRole(VESTING_MANAGER_ROLE)
    nonReentrant
{
    VestingSchedule storage s = schedules[beneficiary][scheduleId];
    if (!s.exists) revert NoSchedule();

    // --- Step 1: Calculate vested and unvested amounts ---
    uint256 vested = _vestedAmount(s);
    if (vested > s.totalAllocation) vested = s.totalAllocation;

    uint256 claimable = vested > s.released ? vested - s.released : 0; // tokens earned but not claimed
    uint256 unvested = s.totalAllocation > vested ? s.totalAllocation - vested : 0; // tokens not yet earned

    // --- Step 2: Pay out any claimable tokens to beneficiary ---
    if (claimable > 0) {
        s.released += claimable;
        totalAllocated -= claimable; // 🔹 keep accounting aligned
        token.safeTransfer(beneficiary, claimable);
        emit TokensClaimed(beneficiary, scheduleId, claimable);
    }

    // --- Step 3: Return unvested tokens back to owner ---
    if (unvested > 0) {
        if (totalAllocated >= unvested) {
            totalAllocated -= unvested;
        } else {
            totalAllocated = 0;
        }
        token.safeTransfer(_msgSender(), unvested);
        //new user can create schedule for the unvested amount
        totalEntitled -= unvested;
    }

    // --- Step 4: Finalize schedule ---
    s.totalAllocation = vested;
    s.exists = false;

    emit ScheduleCancelled(beneficiary, scheduleId, unvested);
}


    function vestedOf(address beneficiary, uint256 scheduleId) external view returns (uint256) {
        VestingSchedule storage s = schedules[beneficiary][scheduleId];
        if (!s.exists) return 0;
        return _vestedAmount(s);
    }

    function claimableOf(address beneficiary, uint256 scheduleId) external view returns (uint256) {
        VestingSchedule storage s = schedules[beneficiary][scheduleId];
        if (!s.exists) return 0;
        uint256 vested = _vestedAmount(s);
        if (vested <= s.released) return 0;
        return vested - s.released;
    }

    function _msgSender()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (address)
    {
        return ERC2771Context._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }

    function _contextSuffixLength()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (uint256)
    {
        return ERC2771Context._contextSuffixLength();
    }

    // AccessControl interface support
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
