// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/*
QAEscrow (USDC-only, EIP-712 backend-signed settlement delay)

What this contract guarantees (v1):
- Merchants stake USDC per appId.
- Orders can only be deposited if (locked + amount) <= staked for that appId.
- Escrow holds funds until releaseAt = now + delaySeconds (delay is backend-signed per order).
- Buyer can open a dispute before releaseAt.
- An arbitrator resolves disputes (buyer wins / merchant wins / split).
- No on-chain rating. Backend uses ratings to decide delaySeconds and signs terms.

Security hardening included:
- Ownable + AccessControl
- SafeERC20 (USDC quirks)
- ReentrancyGuard
- Pausable
- Events for indexing
*/

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract QAEscrow is
    Ownable,
    AccessControl,
    EIP712,
    ReentrancyGuard,
    Pausable
{
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ----------------------------
    // Roles
    // ----------------------------
    bytes32 public constant APP_ADMIN_ROLE       = keccak256("APP_ADMIN_ROLE");
    bytes32 public constant ARBITRATOR_ROLE      = keccak256("ARBITRATOR_ROLE");
    bytes32 public constant SIGNER_ADMIN_ROLE    = keccak256("SIGNER_ADMIN_ROLE");

    // ----------------------------
    // Token + signer
    // ----------------------------
    IERC20 public immutable USDC;
    address public termsSigner;

    // ----------------------------
    // EIP-712 type hash
    // ----------------------------
    bytes32 public constant ESCROW_TERMS_TYPEHASH = keccak256(
        "EscrowTerms(bytes32 appId,bytes32 orderId,address buyer,uint256 amount,uint64 delaySeconds,uint64 expiresAt)"
    );

    struct EscrowTerms {
        bytes32 appId;
        bytes32 orderId;
        address buyer;
        uint256 amount;       // USDC base units (6 decimals)
        uint64 delaySeconds;  // e.g. 604800
        uint64 expiresAt;     // unix seconds
    }

    enum OrderStatus { None, Deposited, Disputed, Released, Refunded }

    struct Order {
        bytes32 appId;
        address buyer;
        address merchant;
        uint256 amount;
        uint64 releaseAt;
        OrderStatus status;
    }

    // orderKey = keccak256(appId, orderId)
    mapping(bytes32 => Order) public orders;

    // stake/capacity per appId
    mapping(bytes32 => uint256) public staked;
    mapping(bytes32 => uint256) public locked;

    // app ownership (v1 registry inside escrow)
    mapping(bytes32 => address) public appOwner;

    // ----------------------------
    // Events
    // ----------------------------
    event TermsSignerUpdated(address indexed oldSigner, address indexed newSigner);

    event AppOwnerUpdated(bytes32 indexed appId, address indexed oldOwner, address indexed newOwner);

    event Staked(bytes32 indexed appId, address indexed merchant, uint256 amount, uint256 stakedTotal);
    event Unstaked(bytes32 indexed appId, address indexed merchant, uint256 amount, uint256 stakedTotal);

    event Deposited(
        bytes32 indexed appId,
        bytes32 indexed orderId,
        bytes32 indexed orderKey,
        address buyer,
        address merchant,
        uint256 amount,
        uint64 releaseAt
    );

    event Claimed(
        bytes32 indexed appId,
        bytes32 indexed orderId,
        bytes32 indexed orderKey,
        address merchant,
        uint256 amount
    );

    event DisputeOpened(
        bytes32 indexed appId,
        bytes32 indexed orderId,
        bytes32 indexed orderKey,
        address buyer
    );

    event DisputeResolved(
        bytes32 indexed appId,
        bytes32 indexed orderId,
        bytes32 indexed orderKey,
        bool buyerWins,
        uint256 buyerAmount,
        uint256 merchantAmount
    );

    // ----------------------------
    // Constructor
    // ----------------------------
    constructor(address usdc, address initialSigner)
    Ownable(msg.sender)
    EIP712("QAEscrow", "1")
    {
        require(usdc != address(0), "USDC=0");
        require(initialSigner != address(0), "signer=0");

        USDC = IERC20(usdc);
        termsSigner = initialSigner;

        // Admin setup
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(APP_ADMIN_ROLE, msg.sender);
        _grantRole(ARBITRATOR_ROLE, msg.sender);
        _grantRole(SIGNER_ADMIN_ROLE, msg.sender);
    }

    // ----------------------------
    // Admin / Ops
    // ----------------------------
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setTermsSigner(address newSigner) external onlyRole(SIGNER_ADMIN_ROLE) {
        require(newSigner != address(0), "signer=0");
        address old = termsSigner;
        termsSigner = newSigner;
        emit TermsSignerUpdated(old, newSigner);
    }

    function setAppOwner(bytes32 appId, address owner) external onlyRole(APP_ADMIN_ROLE) {
        require(owner != address(0), "owner=0");
        address old = appOwner[appId];
        appOwner[appId] = owner;
        emit AppOwnerUpdated(appId, old, owner);
    }

    // Optional: allow the current owner to transfer ownership without admin.
    function transferAppOwner(bytes32 appId, address newOwner) external {
        require(newOwner != address(0), "owner=0");
        require(appOwner[appId] == msg.sender, "not owner");
        address old = appOwner[appId];
        appOwner[appId] = newOwner;
        emit AppOwnerUpdated(appId, old, newOwner);
    }

    // ----------------------------
    // Helpers
    // ----------------------------
    function orderKey(bytes32 appId, bytes32 orderId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(appId, orderId));
    }

    function availableCapacity(bytes32 appId) external view returns (uint256) {
        uint256 s = staked[appId];
        uint256 l = locked[appId];
        if (s <= l) return 0;
        return s - l;
    }

    // ----------------------------
    // Staking (USDC)
    // ----------------------------
    function stake(bytes32 appId, uint256 amount) external nonReentrant whenNotPaused {
        require(amount > 0, "amount=0");
        require(appOwner[appId] == msg.sender, "not owner");

        USDC.safeTransferFrom(msg.sender, address(this), amount);
        staked[appId] += amount;

        emit Staked(appId, msg.sender, amount, staked[appId]);
    }

    function unstake(bytes32 appId, uint256 amount) external nonReentrant whenNotPaused {
        require(amount > 0, "amount=0");
        require(appOwner[appId] == msg.sender, "not owner");
        require(staked[appId] >= amount, "insufficient staked");

        // Cannot break collateral constraint: (staked - amount) >= locked
        require(staked[appId] - amount >= locked[appId], "undercollateralize");

        staked[appId] -= amount;
        USDC.safeTransfer(msg.sender, amount);

        emit Unstaked(appId, msg.sender, amount, staked[appId]);
    }

    // ----------------------------
    // Deposit (buyer pays)
    // ----------------------------
    function depositUsdc(EscrowTerms calldata t, bytes calldata sig)
    external
    nonReentrant
    whenNotPaused
    {
        require(msg.sender == t.buyer, "buyer mismatch");
        require(t.amount > 0, "amount=0");
        require(t.delaySeconds > 0, "delay=0");
        require(block.timestamp <= t.expiresAt, "terms expired");

        address merchant = appOwner[t.appId];
        require(merchant != address(0), "unknown app");

        // stake capacity check
        require(locked[t.appId] + t.amount <= staked[t.appId], "over capacity");

        bytes32 ok = orderKey(t.appId, t.orderId);
        require(orders[ok].status == OrderStatus.None, "order exists");

        // Verify backend signature (EIP-712)
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ESCROW_TERMS_TYPEHASH,
                    t.appId,
                    t.orderId,
                    t.buyer,
                    t.amount,
                    t.delaySeconds,
                    t.expiresAt
                )
            )
        );
        address recovered = ECDSA.recover(digest, sig);
        require(recovered == termsSigner, "bad signature");

        // Pull USDC from buyer
        USDC.safeTransferFrom(msg.sender, address(this), t.amount);

        uint64 releaseAt = uint64(block.timestamp) + t.delaySeconds;

        orders[ok] = Order({
            appId: t.appId,
            buyer: t.buyer,
            merchant: merchant,
            amount: t.amount,
            releaseAt: releaseAt,
            status: OrderStatus.Deposited
        });

        locked[t.appId] += t.amount;

        emit Deposited(t.appId, t.orderId, ok, t.buyer, merchant, t.amount, releaseAt);
    }

    // ----------------------------
    // Claim (merchant gets paid)
    // ----------------------------
    function claim(bytes32 appId, bytes32 orderId)
    external
    nonReentrant
    whenNotPaused
    {
        bytes32 ok = orderKey(appId, orderId);
        Order storage o = orders[ok];

        require(o.status == OrderStatus.Deposited, "not claimable");
        require(msg.sender == o.merchant, "not merchant");
        require(block.timestamp >= o.releaseAt, "too early");

        o.status = OrderStatus.Released;
        locked[appId] -= o.amount;

        USDC.safeTransfer(o.merchant, o.amount);

        emit Claimed(appId, orderId, ok, o.merchant, o.amount);
    }

    // ----------------------------
    // Disputes
    // ----------------------------
    function openDispute(bytes32 appId, bytes32 orderId)
    external
    nonReentrant
    whenNotPaused
    {
        bytes32 ok = orderKey(appId, orderId);
        Order storage o = orders[ok];

        require(o.status == OrderStatus.Deposited, "not disputable");
        require(msg.sender == o.buyer, "not buyer");
        require(block.timestamp < o.releaseAt, "already releasable");

        o.status = OrderStatus.Disputed;

        emit DisputeOpened(appId, orderId, ok, msg.sender);
    }

    /**
     * Resolve dispute:
     * - buyerWins=true  => refund buyer (full or partial)
     * - buyerWins=false => release merchant (full or partial)
     *
     * For split outcomes: pass buyerAmount < o.amount; remainder goes to merchant.
     */
    function resolveDispute(
        bytes32 appId,
        bytes32 orderId,
        bool buyerWins,
        uint256 buyerAmount
    )
    external
    nonReentrant
    whenNotPaused
    onlyRole(ARBITRATOR_ROLE)
    {
        bytes32 ok = orderKey(appId, orderId);
        Order storage o = orders[ok];

        require(o.status == OrderStatus.Disputed, "not disputed");
        require(buyerAmount <= o.amount, "buyerAmount too big");

        uint256 merchantAmount = o.amount - buyerAmount;

        // Unlock first (effects), then transfer (interactions)
        locked[appId] -= o.amount;

        if (buyerWins) {
            // buyer gets buyerAmount; merchant gets remainder (possibly 0)
            o.status = (merchantAmount == 0) ? OrderStatus.Refunded : OrderStatus.Released;
        } else {
            // merchant gets merchantAmount; buyer gets remainder (possibly 0)
            o.status = (buyerAmount == 0) ? OrderStatus.Released : OrderStatus.Refunded;
        }

        // Transfers
        if (buyerAmount > 0) {
            USDC.safeTransfer(o.buyer, buyerAmount);
        }
        if (merchantAmount > 0) {
            USDC.safeTransfer(o.merchant, merchantAmount);
        }

        emit DisputeResolved(appId, orderId, ok, buyerWins, buyerAmount, merchantAmount);
    }

    // ----------------------------
    // Emergency admin recovery (optional)
    // ----------------------------
    /**
     * If you ever need this, keep it tightly controlled and ideally removed later.
     * It prevents stuck funds in weird USDC situations or migrations.
     */
    function emergencyWithdraw(address to, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
    nonReentrant
    {
        require(to != address(0), "to=0");
        USDC.safeTransfer(to, amount);
    }
}
