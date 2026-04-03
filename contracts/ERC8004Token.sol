// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ERC8004Token
 * @notice ERC20 + EIP-2612 Permit + Transfer Fee + Role-Based Access
 * @dev Part of the ERC8004 full system stack
 *
 *  Features:
 *  - Standard ERC20 (transfer, approve, transferFrom)
 *  - EIP-2612 Permit (gasless approvals via EIP-712 signature)
 *  - Configurable transfer fee (basis points) → routed to Treasury
 *  - Fee whitelist (DEX routers, Core, Vault, etc.)
 *  - Pausable transfers (owner/guardian)
 *  - Blacklist (compliance layer)
 *  - Role-based access (ADMIN, FEE_MANAGER, GUARDIAN)
 *  - Mint / Burn (controlled by MINTER_ROLE)
 *  - Max supply cap
 */
contract ERC8004Token {

    // ═══════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event FeeExemptionSet(address indexed account, bool exempt);
    event BlacklistUpdated(address indexed account, bool blacklisted);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);

    // ═══════════════════════════════════════════════════════════
    //  ERRORS
    // ═══════════════════════════════════════════════════════════

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientBalance(uint256 have, uint256 need);
    error InsufficientAllowance(uint256 have, uint256 need);
    error TransfersPaused();
    error AccountBlacklisted(address account);
    error FeeTooHigh(uint256 fee, uint256 max);
    error PermitExpired(uint256 deadline, uint256 current);
    error InvalidPermitSignature();
    error MaxSupplyExceeded(uint256 requested, uint256 maxSupply);
    error Unauthorized(address caller, bytes32 requiredRole);
    error AlreadyInitialized();

    // ═══════════════════════════════════════════════════════════
    //  ROLES
    // ═══════════════════════════════════════════════════════════

    bytes32 public constant ADMIN_ROLE       = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE      = keccak256("MINTER_ROLE");
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    bytes32 public constant GUARDIAN_ROLE    = keccak256("GUARDIAN_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    // ═══════════════════════════════════════════════════════════
    //  ERC20 STORAGE
    // ═══════════════════════════════════════════════════════════

    string  public name;
    string  public symbol;
    uint8   public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public immutable maxSupply;

    mapping(address => uint256)                     public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ═══════════════════════════════════════════════════════════
    //  FEE SYSTEM
    // ═══════════════════════════════════════════════════════════

    /// @dev Fee in basis points (e.g. 100 = 1%)
    uint256 public transferFeeBps;

    /// @dev Absolute cap: 10% max fee
    uint256 public constant MAX_FEE_BPS = 1000;

    /// @dev Basis point denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    address public treasury;

    /// @dev Accounts exempt from paying fees (Core, Vault, DEX routers, etc.)
    mapping(address => bool) public isFeeExempt;

    // ═══════════════════════════════════════════════════════════
    //  PAUSE + BLACKLIST
    // ═══════════════════════════════════════════════════════════

    bool public paused;
    mapping(address => bool) public isBlacklisted;

    // ═══════════════════════════════════════════════════════════
    //  EIP-712 / PERMIT STORAGE
    // ═══════════════════════════════════════════════════════════

    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @dev EIP-2612 typehash
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    mapping(address => uint256) public nonces;

    // ═══════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    /**
     * @param _name         Token name
     * @param _symbol       Token symbol
     * @param _maxSupply    Hard cap (use 0 for unlimited)
     * @param _initialSupply Tokens minted to deployer at launch
     * @param _treasury     Fee recipient address
     * @param _feeBps       Initial transfer fee in basis points
     */
    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _maxSupply,
        uint256 _initialSupply,
        address _treasury,
        uint256 _feeBps
    ) {
        if (_treasury == address(0)) revert ZeroAddress();
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh(_feeBps, MAX_FEE_BPS);
        if (_maxSupply > 0 && _initialSupply > _maxSupply)
            revert MaxSupplyExceeded(_initialSupply, _maxSupply);

        name     = _name;
        symbol   = _symbol;
        maxSupply = _maxSupply; // 0 = unlimited
        treasury  = _treasury;
        transferFeeBps = _feeBps;

        // Build EIP-712 domain separator at deploy time
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(_name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );

        // Bootstrap roles — deployer gets ADMIN
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(FEE_MANAGER_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        // Exempt deployer and treasury from fees
        isFeeExempt[msg.sender] = true;
        isFeeExempt[_treasury]  = true;

        // Mint initial supply
        if (_initialSupply > 0) {
            _mint(msg.sender, _initialSupply);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert Unauthorized(msg.sender, role);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert TransfersPaused();
        _;
    }

    modifier notBlacklisted(address from, address to) {
        if (isBlacklisted[from]) revert AccountBlacklisted(from);
        if (isBlacklisted[to])   revert AccountBlacklisted(to);
        _;
    }

    // ═══════════════════════════════════════════════════════════
    //  ERC20 CORE
    // ═══════════════════════════════════════════════════════════

    function transfer(address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(msg.sender, to)
        returns (bool)
    {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(from, to)
        returns (bool)
    {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance(allowed, amount);
            unchecked { allowance[from][msg.sender] = allowed - amount; }
        }
        _transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount)
        external
        returns (bool)
    {
        _approve(msg.sender, spender, amount);
        return true;
    }

    // ═══════════════════════════════════════════════════════════
    //  EIP-2612 PERMIT
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Approve via EIP-712 signature — no ETH needed from owner.
     * @dev    Spender (or relayer) calls this on behalf of the owner.
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        if (block.timestamp > deadline) revert PermitExpired(deadline, block.timestamp);

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );

        bytes32 hash = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0) || signer != owner) revert InvalidPermitSignature();

        _approve(owner, spender, value);
    }

    // ═══════════════════════════════════════════════════════════
    //  MINT / BURN
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Mint new tokens. Respects maxSupply cap.
     * @dev Callable by MINTER_ROLE only (e.g. Core contract).
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (to == address(0))  revert ZeroAddress();
        if (amount == 0)       revert ZeroAmount();
        _mint(to, amount);
    }

    /**
     * @notice Burn tokens from caller's balance.
     */
    function burn(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        _burn(msg.sender, amount);
    }

    /**
     * @notice Burn tokens from `from` using allowance.
     */
    function burnFrom(address from, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance(allowed, amount);
            unchecked { allowance[from][msg.sender] = allowed - amount; }
        }
        _burn(from, amount);
    }

    // ═══════════════════════════════════════════════════════════
    //  FEE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Update the transfer fee in basis points.
     * @param newFeeBps New fee (0–1000 = 0%–10%)
     */
    function setTransferFee(uint256 newFeeBps) external onlyRole(FEE_MANAGER_ROLE) {
        if (newFeeBps > MAX_FEE_BPS) revert FeeTooHigh(newFeeBps, MAX_FEE_BPS);
        emit FeeUpdated(transferFeeBps, newFeeBps);
        transferFeeBps = newFeeBps;
    }

    /**
     * @notice Change the treasury address that receives fees.
     */
    function setTreasury(address newTreasury) external onlyRole(ADMIN_ROLE) {
        if (newTreasury == address(0)) revert ZeroAddress();
        emit TreasuryUpdated(treasury, newTreasury);
        // Remove old treasury exemption, add new one
        isFeeExempt[treasury]    = false;
        isFeeExempt[newTreasury] = true;
        treasury = newTreasury;
    }

    /**
     * @notice Exempt or un-exempt an address from transfer fees.
     * @dev Use for: Core, Vault, DEX router, bridges, etc.
     */
    function setFeeExempt(address account, bool exempt) external onlyRole(FEE_MANAGER_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        isFeeExempt[account] = exempt;
        emit FeeExemptionSet(account, exempt);
    }

    /**
     * @notice Batch-exempt multiple addresses (saves gas on setup).
     */
    function setFeeExemptBatch(address[] calldata accounts, bool exempt)
        external onlyRole(FEE_MANAGER_ROLE)
    {
        uint256 len = accounts.length;
        for (uint256 i; i < len; ) {
            if (accounts[i] == address(0)) revert ZeroAddress();
            isFeeExempt[accounts[i]] = exempt;
            emit FeeExemptionSet(accounts[i], exempt);
            unchecked { ++i; }
        }
    }

    /**
     * @notice Preview the fee amount for a given transfer.
     * @return fee     The fee deducted and sent to treasury
     * @return netAmount The amount received by `to`
     */
    function previewFee(address from, uint256 amount)
        external view
        returns (uint256 fee, uint256 netAmount)
    {
        if (isFeeExempt[from] || transferFeeBps == 0) {
            return (0, amount);
        }
        fee = (amount * transferFeeBps) / BPS_DENOMINATOR;
        netAmount = amount - fee;
    }

    // ═══════════════════════════════════════════════════════════
    //  PAUSE / BLACKLIST (GUARDIAN)
    // ═══════════════════════════════════════════════════════════

    function pause() external onlyRole(GUARDIAN_ROLE) {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function setBlacklist(address account, bool blacklisted)
        external onlyRole(GUARDIAN_ROLE)
    {
        if (account == address(0)) revert ZeroAddress();
        isBlacklisted[account] = blacklisted;
        emit BlacklistUpdated(account, blacklisted);
    }

    // ═══════════════════════════════════════════════════════════
    //  ROLE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    function renounceRole(bytes32 role) external {
        _roles[role][msg.sender] = false;
        emit RoleRevoked(role, msg.sender, msg.sender);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }

    // ═══════════════════════════════════════════════════════════
    //  VIEW HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @notice Returns remaining mintable supply (0 if uncapped)
    function remainingMintable() external view returns (uint256) {
        if (maxSupply == 0) return type(uint256).max;
        return maxSupply > totalSupply ? maxSupply - totalSupply : 0;
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL LOGIC
    // ═══════════════════════════════════════════════════════════

    function _transfer(address from, address to, uint256 amount) internal {
        if (from == address(0)) revert ZeroAddress();
        if (to   == address(0)) revert ZeroAddress();
        if (amount == 0)        revert ZeroAmount();

        uint256 fromBalance = balanceOf[from];
        if (fromBalance < amount) revert InsufficientBalance(fromBalance, amount);

        // ── Fee calculation ──────────────────────────────────
        uint256 fee;
        uint256 netAmount = amount;

        bool exempt = isFeeExempt[from] || isFeeExempt[to];

        if (!exempt && transferFeeBps > 0) {
            fee       = (amount * transferFeeBps) / BPS_DENOMINATOR;
            netAmount = amount - fee;
        }

        // ── State updates (checks-effects) ──────────────────
        unchecked {
            balanceOf[from] -= amount;            // total out of sender
            balanceOf[to]   += netAmount;         // net into recipient
            if (fee > 0) {
                balanceOf[treasury] += fee;       // fee into treasury
            }
        }

        emit Transfer(from, to, netAmount);
        if (fee > 0) {
            emit Transfer(from, treasury, fee);   // standard ERC20 fee event
        }
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        if (owner   == address(0)) revert ZeroAddress();
        if (spender == address(0)) revert ZeroAddress();
        allowance[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _mint(address to, uint256 amount) internal {
        if (maxSupply > 0 && totalSupply + amount > maxSupply)
            revert MaxSupplyExceeded(totalSupply + amount, maxSupply);

        unchecked {
            totalSupply    += amount;
            balanceOf[to]  += amount;
        }
        emit Transfer(address(0), to, amount);
        emit Mint(to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        uint256 bal = balanceOf[from];
        if (bal < amount) revert InsufficientBalance(bal, amount);
        unchecked {
            balanceOf[from] -= amount;
            totalSupply     -= amount;
        }
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }
}
