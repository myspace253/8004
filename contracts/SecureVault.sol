// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecureVault
 * @notice Isolated fund storage with EIP-712 executor, target whitelist,
 *         and multi-layer reentrancy protection.
 * @dev Part of the ERC8004 full system stack.
 *
 *  Security model:
 *  ┌────────────────────────────────────────────────────────────┐
 *  │  User funds sit here — completely isolated from Core/NFT   │
 *  │  Nothing can move funds without:                           │
 *  │   1. A valid EIP-712 signed TransferRequest               │
 *  │   2. Signature from the vault owner                        │
 *  │   3. Target address being whitelisted                      │
 *  │   4. Executor contract being authorized                    │
 *  │   5. Nonce not yet consumed (replay protection)            │
 *  └────────────────────────────────────────────────────────────┘
 *
 *  Features:
 *  - EIP-712 signed transfer requests (no raw approve pattern)
 *  - Per-target whitelist (only Core, Treasury, etc. can receive)
 *  - Per-token deposit/withdraw tracking
 *  - Nonce-based replay protection
 *  - Emergency withdrawal by vault owner (direct, no signature needed)
 *  - ETH + ERC20 support
 *  - Reentrancy guard (mutex)
 *  - Pausable by guardian
 */
contract SecureVault {

    // ═══════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════

    event Deposited(address indexed token, address indexed from, uint256 amount);
    event ETHDeposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed token, address indexed to, uint256 amount, uint256 nonce);
    event ETHWithdrawn(address indexed to, uint256 amount, uint256 nonce);
    event EmergencyWithdraw(address indexed token, address indexed to, uint256 amount);
    event ExecutorSet(address indexed executor);
    event TargetAllowed(address indexed target, bool allowed);
    event GuardianSet(address indexed guardian);
    event VaultPaused(address indexed by);
    event VaultUnpaused(address indexed by);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    // ═══════════════════════════════════════════════════════════
    //  ERRORS
    // ═══════════════════════════════════════════════════════════

    error ZeroAddress();
    error ZeroAmount();
    error VaultIsPaused();
    error ReentrancyBlocked();
    error NotOwner(address caller);
    error NotGuardian(address caller);
    error NotExecutor(address caller);
    error ExecutorNotSet();
    error TargetNotAllowed(address target);
    error InvalidSignature();
    error NonceAlreadyUsed(uint256 nonce);
    error RequestExpired(uint256 deadline, uint256 current);
    error InsufficientVaultBalance(address token, uint256 have, uint256 need);
    error ETHTransferFailed();
    error TokenTransferFailed();
    error InvalidAmount();

    // ═══════════════════════════════════════════════════════════
    //  EIP-712 TYPES
    // ═══════════════════════════════════════════════════════════

    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "TransferRequest(address token,address to,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant ETH_TRANSFER_TYPEHASH = keccak256(
        "ETHTransferRequest(address to,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    // ═══════════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════════

    address public owner;
    address public guardian;
    address public executor;       // SecureExecutorV2 contract

    bool    public paused;
    uint256 private _lock;         // reentrancy: 1=idle, 2=locked

    /// @dev Per-nonce usage tracking (replay protection)
    mapping(uint256 => bool) public usedNonces;

    /// @dev Whitelisted destination addresses
    mapping(address => bool) public allowedTargets;

    /// @dev ERC20 balances tracked inside vault (token → amount)
    mapping(address => uint256) public vaultBalance;

    /// address(0) = native ETH
    uint256 public ethBalance;

    // ═══════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    /**
     * @param _owner  Address that owns this vault (can emergency withdraw)
     */
    constructor(address _owner) {
        if (_owner == address(0)) revert ZeroAddress();
        owner    = _owner;
        guardian = _owner;
        _lock    = 1;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("ERC8004_VAULT")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian && msg.sender != owner)
            revert NotGuardian(msg.sender);
        _;
    }

    modifier onlyExecutor() {
        if (executor == address(0)) revert ExecutorNotSet();
        if (msg.sender != executor)  revert NotExecutor(msg.sender);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert VaultIsPaused();
        _;
    }

    modifier nonReentrant() {
        if (_lock == 2) revert ReentrancyBlocked();
        _lock = 2;
        _;
        _lock = 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  DEPOSIT
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Deposit ERC20 tokens into the vault.
     * @dev Caller must have approved this vault for `amount` first.
     */
    function deposit(address token, uint256 amount)
        external
        whenNotPaused
        nonReentrant
    {
        if (token  == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();

        bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!ok) revert TokenTransferFailed();

        unchecked { vaultBalance[token] += amount; }

        emit Deposited(token, msg.sender, amount);
    }

    /**
     * @notice Deposit native ETH into the vault.
     */
    receive() external payable {
        if (msg.value == 0) revert ZeroAmount();
        unchecked { ethBalance += msg.value; }
        emit ETHDeposited(msg.sender, msg.value);
    }

    // ═══════════════════════════════════════════════════════════
    //  SIGNED WITHDRAWAL (via Executor)
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Execute a signed ERC20 transfer out of the vault.
     * @dev Only callable by the authorized executor contract.
     *      Executor must have already verified the EIP-712 signature.
     *
     * @param token     ERC20 token to transfer
     * @param to        Destination (must be in allowedTargets)
     * @param amount    Amount to transfer
     * @param nonce     Unique nonce (prevent replay)
     * @param deadline  Request expiry timestamp
     * @param signature Owner's EIP-712 signature over the request
     */
    function executeTransfer(
        address token,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    )
        external
        onlyExecutor
        whenNotPaused
        nonReentrant
    {
        // ── Pre-checks ──────────────────────────────────────
        if (token  == address(0)) revert ZeroAddress();
        if (to     == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();
        if (block.timestamp > deadline) revert RequestExpired(deadline, block.timestamp);
        if (usedNonces[nonce])    revert NonceAlreadyUsed(nonce);
        if (!allowedTargets[to])  revert TargetNotAllowed(to);

        uint256 bal = vaultBalance[token];
        if (bal < amount) revert InsufficientVaultBalance(token, bal, amount);

        // ── Verify EIP-712 signature ─────────────────────────
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_TYPEHASH, token, to, amount, nonce, deadline)
        );
        _verifySignature(structHash, signature);

        // ── State update (CEI) ───────────────────────────────
        usedNonces[nonce] = true;
        unchecked { vaultBalance[token] -= amount; }

        // ── External call last ───────────────────────────────
        bool ok = IERC20(token).transfer(to, amount);
        if (!ok) revert TokenTransferFailed();

        emit Withdrawn(token, to, amount, nonce);
    }

    /**
     * @notice Execute a signed ETH transfer out of the vault.
     */
    function executeETHTransfer(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    )
        external
        onlyExecutor
        whenNotPaused
        nonReentrant
    {
        if (to     == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();
        if (block.timestamp > deadline) revert RequestExpired(deadline, block.timestamp);
        if (usedNonces[nonce])    revert NonceAlreadyUsed(nonce);
        if (!allowedTargets[to])  revert TargetNotAllowed(to);
        if (ethBalance < amount)  revert InsufficientVaultBalance(address(0), ethBalance, amount);

        bytes32 structHash = keccak256(
            abi.encode(ETH_TRANSFER_TYPEHASH, to, amount, nonce, deadline)
        );
        _verifySignature(structHash, signature);

        usedNonces[nonce] = true;
        unchecked { ethBalance -= amount; }

        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert ETHTransferFailed();

        emit ETHWithdrawn(to, amount, nonce);
    }

    // ═══════════════════════════════════════════════════════════
    //  EMERGENCY WITHDRAWAL (owner only, no signature needed)
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Owner can always pull any ERC20 token out of the vault.
     * @dev Use in case executor/guardian is compromised.
     */
    function emergencyWithdrawToken(address token, address to, uint256 amount)
        external
        onlyOwner
        nonReentrant
    {
        if (token  == address(0)) revert ZeroAddress();
        if (to     == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();

        uint256 bal = vaultBalance[token];
        if (bal < amount) revert InsufficientVaultBalance(token, bal, amount);

        unchecked { vaultBalance[token] -= amount; }

        bool ok = IERC20(token).transfer(to, amount);
        if (!ok) revert TokenTransferFailed();

        emit EmergencyWithdraw(token, to, amount);
    }

    /**
     * @notice Owner can always pull ETH out of the vault.
     */
    function emergencyWithdrawETH(address to, uint256 amount)
        external
        onlyOwner
        nonReentrant
    {
        if (to     == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();
        if (ethBalance < amount)  revert InsufficientVaultBalance(address(0), ethBalance, amount);

        unchecked { ethBalance -= amount; }

        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert ETHTransferFailed();

        emit EmergencyWithdraw(address(0), to, amount);
    }

    // ═══════════════════════════════════════════════════════════
    //  CONFIGURATION (owner)
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Set the authorized executor contract.
     * @dev Only one executor at a time. Set to address(0) to disable all outflows.
     */
    function setExecutor(address _executor) external onlyOwner {
        executor = _executor;
        emit ExecutorSet(_executor);
    }

    /**
     * @notice Whitelist or remove a target address.
     * @dev Only whitelisted addresses can receive funds from executeTransfer.
     */
    function setAllowedTarget(address target, bool allowed) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        allowedTargets[target] = allowed;
        emit TargetAllowed(target, allowed);
    }

    /**
     * @notice Batch set target allowances (gas-efficient setup).
     */
    function setAllowedTargetBatch(address[] calldata targets, bool allowed)
        external onlyOwner
    {
        uint256 len = targets.length;
        for (uint256 i; i < len; ) {
            if (targets[i] == address(0)) revert ZeroAddress();
            allowedTargets[targets[i]] = allowed;
            emit TargetAllowed(targets[i], allowed);
            unchecked { ++i; }
        }
    }

    function setGuardian(address _guardian) external onlyOwner {
        if (_guardian == address(0)) revert ZeroAddress();
        guardian = _guardian;
        emit GuardianSet(_guardian);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ═══════════════════════════════════════════════════════════
    //  PAUSE (GUARDIAN)
    // ═══════════════════════════════════════════════════════════

    function pause()   external onlyGuardian { paused = true;  emit VaultPaused(msg.sender);   }
    function unpause() external onlyGuardian { paused = false; emit VaultUnpaused(msg.sender); }

    // ═══════════════════════════════════════════════════════════
    //  VIEW HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @notice Check if a nonce has already been used
    function isNonceUsed(uint256 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }

    /// @notice Returns the EIP-712 hash of a TransferRequest (for front-end signing)
    function hashTransferRequest(
        address token, address to, uint256 amount, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_TYPEHASH, token, to, amount, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Returns the EIP-712 hash of an ETHTransferRequest
    function hashETHTransferRequest(
        address to, uint256 amount, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ETH_TRANSFER_TYPEHASH, to, amount, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL: SIGNATURE VERIFICATION
    // ═══════════════════════════════════════════════════════════

    /**
     * @dev Recovers signer from an EIP-712 struct hash and verifies it equals `owner`.
     *      Supports both 65-byte ECDSA and EIP-2098 compact (64-byte) signatures.
     */
    function _verifySignature(bytes32 structHash, bytes calldata signature) internal view {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer;

        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8   v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
            signer = ecrecover(digest, v, r, s);

        } else if (signature.length == 64) {
            // EIP-2098 compact signature
            bytes32 r;
            bytes32 vs;
            assembly {
                r  := calldataload(signature.offset)
                vs := calldataload(add(signature.offset, 32))
            }
            bytes32 s_ = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            uint8   v_ = uint8((uint256(vs) >> 255) + 27);
            signer = ecrecover(digest, v_, r, s_);

        } else {
            revert InvalidSignature();
        }

        if (signer == address(0) || signer != owner)
            revert InvalidSignature();
    }
}

// ═══════════════════════════════════════════════════════════════
//  MINIMAL ERC20 INTERFACE
// ═══════════════════════════════════════════════════════════════

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
