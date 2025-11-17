// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";


/**
 * @title RMDTTokenGasLess
 * @notice Fixed-supply ERC20 token supporting gasless transfers via both EIP-2771 (trusted forwarder)
 *         and EIP-712 (signature-based trustless meta-tx using ERC20Permit).
 */
contract RMDTTokenGasLess is ERC20Permit, Ownable2Step, ERC2771Context, ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

     address public wrapperContract;

    uint256 public constant MAX_SUPPLY = 50_000_000_000 * (10 ** 18);
    mapping(address => uint256) public metaNonces; // distinct name

    bytes32 private constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address from,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    event RecoveredERC20(address indexed token, address indexed to, uint256 amount);
    event MetaTransferRelayed(address indexed relayer, address indexed from, address indexed to, uint256 amount);

    // Admin roles to separate responsibilities
    bytes32 public constant WRAPPER_MANAGER_ROLE = keccak256("WRAPPER_MANAGER_ROLE");
    bytes32 public constant RESCUER_ROLE = keccak256("RESCUER_ROLE");

    constructor(
        string memory name_,
        string memory symbol_,
        address initialRecipient,
        address initialOwner,
        address trustedForwarder,
        address _wrapperContract
    )
        ERC20(name_, symbol_)
        ERC20Permit(name_)                // includes EIP712 initialization
        Ownable(initialOwner)
        ERC2771Context(trustedForwarder)
    {
        require(initialRecipient != address(0), "ZeroRecipient");
        require(initialOwner != address(0), "ZeroOwner");
        _mint(initialRecipient, MAX_SUPPLY);
        wrapperContract =_wrapperContract;

        // Grant AccessControl roles to initial owner (timelock in production)
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(WRAPPER_MANAGER_ROLE, initialOwner);
        _grantRole(RESCUER_ROLE, initialOwner);
    }

      /// Allow only trusted forwarder or wrapper
    function _isAuthorizedRelayer(address sender) internal view returns (bool) {
       return sender == trustedForwarder() || sender == wrapperContract;
    }

    /**
     * @notice Gasless meta-transfer via EIP-712 signature (trustless).
     */
function transferWithSignature(
    address from,
    address to,
    uint256 amount,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
) external nonReentrant {
    require(_isAuthorizedRelayer(msg.sender), "NotAuthorizedRelayer");
    require(block.timestamp <= deadline, "SignatureExpired");
    require(nonce == metaNonces[from], "InvalidNonce");
    require(to != address(0), "ZeroAddress");

    bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, amount, nonce, deadline));
    bytes32 digest = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(digest, signature);
    require(signer == from, "InvalidSignature");

    metaNonces[from] = nonce + 1; // ✅ updated

    _transfer(from, to, amount);
    emit MetaTransferRelayed( msg.sender, from, to, amount);
}


    function setWrapperContract(address newWrapper) external onlyRole(WRAPPER_MANAGER_ROLE) {
        require(newWrapper != address(0), "ZeroWrapper");
        wrapperContract = newWrapper;
    }

    /**
     * @notice Recover accidentally sent ERC20 tokens (not RMDT itself).
     */
    function recoverERC20(address token, address to, uint256 amount) external onlyRole(RESCUER_ROLE) {
        require(token != address(this), "CannotRecoverSelf");
        require(to != address(0), "ZeroAddress");
        IERC20(token).safeTransfer(to, amount);
        emit RecoveredERC20(token, to, amount);
    }

    // ERC2771Context overrides
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
