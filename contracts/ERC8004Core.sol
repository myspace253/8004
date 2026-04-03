// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ERC8004Core
 * @notice Business logic layer — the brain of the ERC8004 system.
 * @dev Part of the ERC8004 full system stack.
 *
 *  Responsibilities:
 *  - Service subscription (pay ERC8004Token → mint Service NFT)
 *  - Tier upgrades (pay token delta → upgrade NFT tier)
 *  - Token burn mechanics (deflationary pressure)
 *  - Fee routing to Treasury
 *  - Reentrancy protected
 *  - Pausable
 *  - Role-based admin
 *
 *  Payment flow:
 *    User → permit/approve ERC8004Token
 *         → Core.subscribe(tier)
 *         → Core splits payment: burn% + treasury%
 *         → Core calls NFT.mint(user, tier)
 */
contract ERC8004Core {

    // ═══════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════

    event Subscribed(
        address indexed user,
        uint256 indexed tokenId,
        IServiceNFT.Tier tier,
        uint256 amountPaid
    );
    event TierUpgraded(
        address indexed user,
        uint256 indexed tokenId,
        IServiceNFT.Tier oldTier,
        IServiceNFT.Tier newTier,
        uint256 amountPaid
    );
    event TierPriceUpdated(IServiceNFT.Tier indexed tier, uint256 price);
    event BurnRatioUpdated(uint256 oldRatio, uint256 newRatio);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event FeeExemptionSet(address indexed account, bool exempt);

    // ═══════════════════════════════════════════════════════════
    //  ERRORS
    // ═══════════════════════════════════════════════════════════

    error ZeroAddress();
    error ZeroAmount();
    error CorePaused();
    error ReentrancyGuard();
    error Unauthorized(address caller, bytes32 role);
    error InvalidTier();
    error TierPriceNotSet(IServiceNFT.Tier tier);
    error InsufficientPayment(uint256 sent, uint256 required);
    error NotTokenOwner(address caller, uint256 tokenId);
    error InvalidUpgradePath(IServiceNFT.Tier current, IServiceNFT.Tier target);
    error BurnRatioTooHigh(uint256 ratio, uint256 max);
    error TransferFailed();

    // ═══════════════════════════════════════════════════════════
    //  ROLES
    // ═══════════════════════════════════════════════════════════

    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    // ═══════════════════════════════════════════════════════════
    //  SYSTEM REFERENCES
    // ═══════════════════════════════════════════════════════════

    IERC8004Token  public immutable token;
    IServiceNFT    public immutable nft;
    address        public           treasury;

    // ═══════════════════════════════════════════════════════════
    //  PRICING
    // ═══════════════════════════════════════════════════════════

    /// @dev Price in ERC8004Token (18 decimals) per tier
    mapping(IServiceNFT.Tier => uint256) public tierPrice;

    /// @dev Basis points of each payment that gets burned (deflationary)
    /// Remainder goes to treasury.
    /// e.g. burnRatioBps = 2000 → 20% burned, 80% treasury
    uint256 public burnRatioBps;
    uint256 public constant MAX_BURN_BPS  = 9000; // max 90% burn
    uint256 public constant BPS_DENOM     = 10_000;

    // ═══════════════════════════════════════════════════════════
    //  ACCOUNTING
    // ═══════════════════════════════════════════════════════════

    uint256 public totalRevenue;
    uint256 public totalBurned;
    uint256 public totalSubscriptions;
    uint256 public totalUpgrades;

    mapping(address => uint256[]) private _userTokens;

    // ═══════════════════════════════════════════════════════════
    //  GUARDS
    // ═══════════════════════════════════════════════════════════

    bool    public paused;
    uint256 private _reentrancyStatus; // 1 = idle, 2 = locked

    // ═══════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    /**
     * @param _token    ERC8004Token address
     * @param _nft      ERC8004ServiceNFT address
     * @param _treasury Treasury address
     */
    constructor(address _token, address _nft, address _treasury) {
        if (_token    == address(0)) revert ZeroAddress();
        if (_nft      == address(0)) revert ZeroAddress();
        if (_treasury == address(0)) revert ZeroAddress();

        token    = IERC8004Token(_token);
        nft      = IServiceNFT(_nft);
        treasury = _treasury;

        burnRatioBps = 2000; // 20% burned by default

        _grantRole(ADMIN_ROLE,    msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        _reentrancyStatus = 1;

        // Set default prices (in token units, 18 decimals)
        tierPrice[IServiceNFT.Tier.BASIC]   = 100  * 1e18;
        tierPrice[IServiceNFT.Tier.PRO]     = 500  * 1e18;
        tierPrice[IServiceNFT.Tier.ELITE]   = 2000 * 1e18;
        tierPrice[IServiceNFT.Tier.GENESIS] = 10000 * 1e18;
    }

    // ═══════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert Unauthorized(msg.sender, role);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert CorePaused();
        _;
    }

    modifier nonReentrant() {
        if (_reentrancyStatus == 2) revert ReentrancyGuard();
        _reentrancyStatus = 2;
        _;
        _reentrancyStatus = 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  CORE: SUBSCRIBE
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Subscribe to a service tier by paying ERC8004Token.
     * @dev Caller must have approved (or permit'd) enough tokens first.
     *      Payment is split: burnRatioBps% burned, rest → treasury.
     * @param tier   Desired service tier (0=BASIC, 1=PRO, 2=ELITE, 3=GENESIS)
     * @return tokenId  The minted Service NFT token ID
     */
    function subscribe(IServiceNFT.Tier tier)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 tokenId)
    {
        uint256 price = tierPrice[tier];
        if (price == 0) revert TierPriceNotSet(tier);

        // Pull payment from user
        _pullPayment(msg.sender, price);
        // Route payment
        _routePayment(price);

        // Mint NFT
        tokenId = nft.mint(msg.sender, tier);
        _userTokens[msg.sender].push(tokenId);

        unchecked {
            totalRevenue       += price;
            totalSubscriptions += 1;
        }

        emit Subscribed(msg.sender, tokenId, tier, price);
    }

    /**
     * @notice Subscribe using EIP-2612 Permit — no prior approval tx needed.
     * @dev One-tx UX: user signs permit off-chain, relayer/self calls this.
     */
    function subscribeWithPermit(
        IServiceNFT.Tier tier,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    )
        external
        whenNotPaused
        nonReentrant
        returns (uint256 tokenId)
    {
        uint256 price = tierPrice[tier];
        if (price == 0) revert TierPriceNotSet(tier);

        // Execute permit — sets allowance in one shot
        token.permit(msg.sender, address(this), price, deadline, v, r, s);

        _pullPayment(msg.sender, price);
        _routePayment(price);

        tokenId = nft.mint(msg.sender, tier);
        _userTokens[msg.sender].push(tokenId);

        unchecked {
            totalRevenue       += price;
            totalSubscriptions += 1;
        }

        emit Subscribed(msg.sender, tokenId, tier, price);
    }

    // ═══════════════════════════════════════════════════════════
    //  CORE: UPGRADE
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Upgrade an existing NFT to a higher tier.
     * @dev User pays the price delta (newTier price - currentTier price).
     * @param tokenId   NFT token to upgrade
     * @param newTier   Target tier (must be higher than current)
     */
    function upgradeTier(uint256 tokenId, IServiceNFT.Tier newTier)
        external
        whenNotPaused
        nonReentrant
    {
        // Verify ownership
        if (nft.ownerOf(tokenId) != msg.sender)
            revert NotTokenOwner(msg.sender, tokenId);

        (IServiceNFT.Tier currentTier,,) = nft.tokenData(tokenId);

        if (uint8(newTier) <= uint8(currentTier))
            revert InvalidUpgradePath(currentTier, newTier);

        uint256 currentPrice = tierPrice[currentTier];
        uint256 newPrice     = tierPrice[newTier];
        if (newPrice == 0) revert TierPriceNotSet(newTier);

        uint256 delta = newPrice > currentPrice ? newPrice - currentPrice : 0;

        if (delta > 0) {
            _pullPayment(msg.sender, delta);
            _routePayment(delta);
            unchecked { totalRevenue += delta; }
        }

        nft.upgradeTier(tokenId, newTier);

        unchecked { totalUpgrades += 1; }

        emit TierUpgraded(msg.sender, tokenId, currentTier, newTier, delta);
    }

    /**
     * @notice Upgrade tier using EIP-2612 Permit.
     */
    function upgradeTierWithPermit(
        uint256 tokenId,
        IServiceNFT.Tier newTier,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    )
        external
        whenNotPaused
        nonReentrant
    {
        if (nft.ownerOf(tokenId) != msg.sender)
            revert NotTokenOwner(msg.sender, tokenId);

        (IServiceNFT.Tier currentTier,,) = nft.tokenData(tokenId);
        if (uint8(newTier) <= uint8(currentTier))
            revert InvalidUpgradePath(currentTier, newTier);

        uint256 delta = tierPrice[newTier] - tierPrice[currentTier];

        if (delta > 0) {
            token.permit(msg.sender, address(this), delta, deadline, v, r, s);
            _pullPayment(msg.sender, delta);
            _routePayment(delta);
            unchecked { totalRevenue += delta; }
        }

        nft.upgradeTier(tokenId, newTier);
        unchecked { totalUpgrades += 1; }

        emit TierUpgraded(msg.sender, tokenId, currentTier, newTier, delta);
    }

    // ═══════════════════════════════════════════════════════════
    //  PRICE MANAGEMENT (OPERATOR)
    // ═══════════════════════════════════════════════════════════

    function setTierPrice(IServiceNFT.Tier tier, uint256 price)
        external onlyRole(OPERATOR_ROLE)
    {
        tierPrice[tier] = price;
        emit TierPriceUpdated(tier, price);
    }

    function setBurnRatio(uint256 newRatioBps) external onlyRole(ADMIN_ROLE) {
        if (newRatioBps > MAX_BURN_BPS) revert BurnRatioTooHigh(newRatioBps, MAX_BURN_BPS);
        emit BurnRatioUpdated(burnRatioBps, newRatioBps);
        burnRatioBps = newRatioBps;
    }

    function setTreasury(address newTreasury) external onlyRole(ADMIN_ROLE) {
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
    }

    // ═══════════════════════════════════════════════════════════
    //  PAUSE (GUARDIAN)
    // ═══════════════════════════════════════════════════════════

    function pause()   external onlyRole(GUARDIAN_ROLE) { paused = true;  emit Paused(msg.sender);   }
    function unpause() external onlyRole(GUARDIAN_ROLE) { paused = false; emit Unpaused(msg.sender); }

    // ═══════════════════════════════════════════════════════════
    //  VIEW HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @notice Returns all token IDs subscribed by a user via Core
    function userTokens(address user) external view returns (uint256[] memory) {
        return _userTokens[user];
    }

    /// @notice Preview the burn + treasury split for a given amount
    function previewPaymentSplit(uint256 amount)
        external view
        returns (uint256 burnAmount, uint256 treasuryAmount)
    {
        burnAmount     = (amount * burnRatioBps) / BPS_DENOM;
        treasuryAmount = amount - burnAmount;
    }

    // ═══════════════════════════════════════════════════════════
    //  ROLE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = false;
        emit RoleRevoked(role, account);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL
    // ═══════════════════════════════════════════════════════════

    function _pullPayment(address from, uint256 amount) internal {
        bool ok = token.transferFrom(from, address(this), amount);
        if (!ok) revert TransferFailed();
    }

    function _routePayment(uint256 amount) internal {
        uint256 burnAmount     = (amount * burnRatioBps) / BPS_DENOM;
        uint256 treasuryAmount = amount - burnAmount;

        if (burnAmount > 0) {
            token.burn(burnAmount);
            unchecked { totalBurned += burnAmount; }
        }

        if (treasuryAmount > 0) {
            bool ok = token.transfer(treasury, treasuryAmount);
            if (!ok) revert TransferFailed();
        }
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
        emit RoleGranted(role, account);
    }
}

// ═══════════════════════════════════════════════════════════════
//  MINIMAL INTERFACES (avoid circular imports)
// ═══════════════════════════════════════════════════════════════

interface IERC8004Token {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function burn(uint256 amount) external;
    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external;
}

interface IServiceNFT {
    enum Tier { BASIC, PRO, ELITE, GENESIS }
    function mint(address to, Tier tier) external returns (uint256 tokenId);
    function upgradeTier(uint256 tokenId, Tier newTier) external;
    function ownerOf(uint256 tokenId) external view returns (address);
    function tokenData(uint256 tokenId) external view returns (Tier tier, address owner, uint48 mintedAt);
}
