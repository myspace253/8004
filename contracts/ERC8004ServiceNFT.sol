// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ERC8004ServiceNFT
 * @notice ERC721 Service NFT with Tier system, on-chain metadata, and role-based minting.
 * @dev Part of the ERC8004 full system stack.
 *
 *  Tiers:
 *   0 = BASIC    — entry-level access
 *   1 = PRO      — extended features
 *   2 = ELITE    — full system access
 *   3 = GENESIS  — founding member, non-transferable option
 *
 *  Features:
 *  - ERC721 standard (transfer, approve, safeTransferFrom)
 *  - Per-token tier tracking
 *  - Per-tier supply caps
 *  - Per-tier transferability lock (soulbound option)
 *  - Per-token IPFS/URI metadata
 *  - Role-based minting (MINTER_ROLE → Core contract)
 *  - Tier upgrade path (MINTER_ROLE controls upgrades)
 *  - ERC721Enumerable-style owner token listing
 *  - Royalty info (EIP-2981)
 */
contract ERC8004ServiceNFT {

    // ═══════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    event ServiceNFTMinted(address indexed to, uint256 indexed tokenId, Tier tier);
    event TierUpgraded(uint256 indexed tokenId, Tier oldTier, Tier newTier);
    event TierConfigUpdated(Tier indexed tier, uint256 maxSupply, bool transferable);
    event BaseURIUpdated(string newBaseURI);
    event TokenURISet(uint256 indexed tokenId, string uri);
    event RoyaltyUpdated(address receiver, uint96 feeBps);
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    // ═══════════════════════════════════════════════════════════
    //  ERRORS
    // ═══════════════════════════════════════════════════════════

    error ZeroAddress();
    error TokenDoesNotExist(uint256 tokenId);
    error NotOwnerNorApproved(address caller, uint256 tokenId);
    error TransferNotAllowed(uint256 tokenId, Tier tier);
    error TierCapReached(Tier tier, uint256 cap);
    error InvalidTierUpgrade(Tier current, Tier requested);
    error Unauthorized(address caller, bytes32 requiredRole);
    error InvalidRoyaltyBps(uint96 bps);
    error ERC721ReceiverRejected();

    // ═══════════════════════════════════════════════════════════
    //  TYPES
    // ═══════════════════════════════════════════════════════════

    enum Tier { BASIC, PRO, ELITE, GENESIS }

    struct TierConfig {
        uint256 maxSupply;    // 0 = unlimited
        uint256 minted;       // total minted in this tier
        bool    transferable; // false = soulbound
    }

    struct TokenData {
        Tier    tier;
        address owner;
        string  uri;          // override; falls back to baseURI + tokenId
        uint48  mintedAt;
    }

    // ═══════════════════════════════════════════════════════════
    //  ROLES
    // ═══════════════════════════════════════════════════════════

    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE  = keccak256("MINTER_ROLE");
    bytes32 public constant URI_ROLE     = keccak256("URI_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    // ═══════════════════════════════════════════════════════════
    //  ERC721 STORAGE
    // ═══════════════════════════════════════════════════════════

    string public name;
    string public symbol;
    string public baseURI;

    uint256 public totalSupply;
    uint256 private _nextTokenId = 1;

    mapping(uint256 => TokenData)                   private _tokens;
    mapping(address => uint256)                      public  balanceOf;
    mapping(uint256 => address)                      private _tokenApprovals;
    mapping(address => mapping(address => bool))     private _operatorApprovals;

    /// @dev owner → list of owned token ids (enumerable)
    mapping(address => uint256[]) private _ownedTokens;
    /// @dev tokenId → index in owner's _ownedTokens array
    mapping(uint256 => uint256)   private _ownedTokenIndex;

    // ═══════════════════════════════════════════════════════════
    //  TIER STORAGE
    // ═══════════════════════════════════════════════════════════

    mapping(Tier => TierConfig) public tierConfig;

    // ═══════════════════════════════════════════════════════════
    //  EIP-2981 ROYALTY
    // ═══════════════════════════════════════════════════════════

    address public royaltyReceiver;
    uint96  public royaltyBps;      // e.g. 500 = 5%

    // ═══════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    constructor() {
        name   = "ERC8004 Service NFT";
        symbol = "SVC8004";

        _grantRole(ADMIN_ROLE,  msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(URI_ROLE,    msg.sender);

        royaltyReceiver = msg.sender;
        royaltyBps      = 500; // 5% default

        // Default tier configs
        tierConfig[Tier.BASIC]   = TierConfig({ maxSupply: 10_000, minted: 0, transferable: true  });
        tierConfig[Tier.PRO]     = TierConfig({ maxSupply: 3_000,  minted: 0, transferable: true  });
        tierConfig[Tier.ELITE]   = TierConfig({ maxSupply: 500,    minted: 0, transferable: true  });
        tierConfig[Tier.GENESIS] = TierConfig({ maxSupply: 100,    minted: 0, transferable: false }); // soulbound
    }

    // ═══════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert Unauthorized(msg.sender, role);
        _;
    }

    modifier tokenExists(uint256 tokenId) {
        if (_tokens[tokenId].owner == address(0)) revert TokenDoesNotExist(tokenId);
        _;
    }

    // ═══════════════════════════════════════════════════════════
    //  ERC721 CORE
    // ═══════════════════════════════════════════════════════════

    function ownerOf(uint256 tokenId) public view tokenExists(tokenId) returns (address) {
        return _tokens[tokenId].owner;
    }

    function getApproved(uint256 tokenId) public view tokenExists(tokenId) returns (address) {
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function approve(address to, uint256 tokenId) external {
        address owner = ownerOf(tokenId);
        if (msg.sender != owner && !isApprovedForAll(owner, msg.sender))
            revert NotOwnerNorApproved(msg.sender, tokenId);
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        if (to == address(0)) revert ZeroAddress();
        _checkTransferAuth(from, tokenId);
        _checkTierTransferable(tokenId);
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        transferFrom(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    // ═══════════════════════════════════════════════════════════
    //  MINT
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Mint a new Service NFT to `to` at the given tier.
     * @dev Called by Core contract (MINTER_ROLE).
     * @return tokenId The newly minted token ID.
     */
    function mint(address to, Tier tier)
        external
        onlyRole(MINTER_ROLE)
        returns (uint256 tokenId)
    {
        if (to == address(0)) revert ZeroAddress();

        TierConfig storage cfg = tierConfig[tier];
        if (cfg.maxSupply > 0 && cfg.minted >= cfg.maxSupply)
            revert TierCapReached(tier, cfg.maxSupply);

        tokenId = _nextTokenId++;
        cfg.minted++;
        totalSupply++;

        _tokens[tokenId] = TokenData({
            tier:     tier,
            owner:    to,
            uri:      "",
            mintedAt: uint48(block.timestamp)
        });

        _addTokenToOwner(to, tokenId);
        balanceOf[to]++;

        emit Transfer(address(0), to, tokenId);
        emit ServiceNFTMinted(to, tokenId, tier);
    }

    /**
     * @notice Mint with a specific IPFS URI override.
     */
    function mintWithURI(address to, Tier tier, string calldata uri)
        external
        onlyRole(MINTER_ROLE)
        returns (uint256 tokenId)
    {
        tokenId = this.mint(to, tier);
        _tokens[tokenId].uri = uri;
        emit TokenURISet(tokenId, uri);
    }

    // ═══════════════════════════════════════════════════════════
    //  TIER UPGRADE
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Upgrade a token's tier. Must be strictly ascending.
     * @dev Called by Core after payment/burn is verified.
     */
    function upgradeTier(uint256 tokenId, Tier newTier)
        external
        onlyRole(MINTER_ROLE)
        tokenExists(tokenId)
    {
        Tier current = _tokens[tokenId].tier;
        if (uint8(newTier) <= uint8(current))
            revert InvalidTierUpgrade(current, newTier);

        TierConfig storage cfg = tierConfig[newTier];
        if (cfg.maxSupply > 0 && cfg.minted >= cfg.maxSupply)
            revert TierCapReached(newTier, cfg.maxSupply);

        // Decrement old tier count, increment new
        tierConfig[current].minted--;
        cfg.minted++;

        _tokens[tokenId].tier = newTier;
        emit TierUpgraded(tokenId, current, newTier);
    }

    // ═══════════════════════════════════════════════════════════
    //  METADATA
    // ═══════════════════════════════════════════════════════════

    function tokenURI(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (string memory)
    {
        string memory override_ = _tokens[tokenId].uri;
        if (bytes(override_).length > 0) return override_;

        if (bytes(baseURI).length == 0) return "";

        return string(abi.encodePacked(baseURI, _toString(tokenId)));
    }

    function setBaseURI(string calldata uri) external onlyRole(URI_ROLE) {
        baseURI = uri;
        emit BaseURIUpdated(uri);
    }

    function setTokenURI(uint256 tokenId, string calldata uri)
        external
        onlyRole(URI_ROLE)
        tokenExists(tokenId)
    {
        _tokens[tokenId].uri = uri;
        emit TokenURISet(tokenId, uri);
    }

    // ═══════════════════════════════════════════════════════════
    //  TIER CONFIG (ADMIN)
    // ═══════════════════════════════════════════════════════════

    function setTierConfig(Tier tier, uint256 maxSupply, bool transferable)
        external
        onlyRole(ADMIN_ROLE)
    {
        TierConfig storage cfg = tierConfig[tier];
        cfg.maxSupply    = maxSupply;
        cfg.transferable = transferable;
        emit TierConfigUpdated(tier, maxSupply, transferable);
    }

    // ═══════════════════════════════════════════════════════════
    //  EIP-2981 ROYALTY
    // ═══════════════════════════════════════════════════════════

    function royaltyInfo(uint256 /*tokenId*/, uint256 salePrice)
        external
        view
        returns (address receiver, uint256 royaltyAmount)
    {
        receiver      = royaltyReceiver;
        royaltyAmount = (salePrice * royaltyBps) / 10_000;
    }

    function setRoyalty(address receiver, uint96 bps) external onlyRole(ADMIN_ROLE) {
        if (receiver == address(0)) revert ZeroAddress();
        if (bps > 1000) revert InvalidRoyaltyBps(bps); // max 10%
        royaltyReceiver = receiver;
        royaltyBps      = bps;
        emit RoyaltyUpdated(receiver, bps);
    }

    // ═══════════════════════════════════════════════════════════
    //  ENUMERABLE HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @notice Returns all token IDs owned by `owner`
    function tokensOfOwner(address owner) external view returns (uint256[] memory) {
        return _ownedTokens[owner];
    }

    /// @notice Returns full token data for a given tokenId
    function tokenData(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (Tier tier, address owner, uint48 mintedAt)
    {
        TokenData storage d = _tokens[tokenId];
        return (d.tier, d.owner, d.mintedAt);
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
    //  ERC165 INTERFACE SUPPORT
    // ═══════════════════════════════════════════════════════════

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x80ac58cd || // ERC721
            interfaceId == 0x5b5e139f || // ERC721Metadata
            interfaceId == 0x2a55205a || // ERC2981 Royalty
            interfaceId == 0x01ffc9a7;   // ERC165
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL
    // ═══════════════════════════════════════════════════════════

    function _transfer(address from, address to, uint256 tokenId) internal {
        _tokens[tokenId].owner = to;
        delete _tokenApprovals[tokenId];

        _removeTokenFromOwner(from, tokenId);
        _addTokenToOwner(to, tokenId);

        unchecked {
            balanceOf[from]--;
            balanceOf[to]++;
        }

        emit Transfer(from, to, tokenId);
    }

    function _checkTransferAuth(address from, uint256 tokenId) internal view {
        address owner = ownerOf(tokenId);
        if (from != owner) revert NotOwnerNorApproved(from, tokenId);
        if (
            msg.sender != owner &&
            !isApprovedForAll(owner, msg.sender) &&
            getApproved(tokenId) != msg.sender
        ) revert NotOwnerNorApproved(msg.sender, tokenId);
    }

    function _checkTierTransferable(uint256 tokenId) internal view {
        Tier tier = _tokens[tokenId].tier;
        if (!tierConfig[tier].transferable)
            revert TransferNotAllowed(tokenId, tier);
    }

    function _addTokenToOwner(address owner, uint256 tokenId) internal {
        _ownedTokenIndex[tokenId] = _ownedTokens[owner].length;
        _ownedTokens[owner].push(tokenId);
    }

    function _removeTokenFromOwner(address owner, uint256 tokenId) internal {
        uint256 lastIndex = _ownedTokens[owner].length - 1;
        uint256 tokenIndex = _ownedTokenIndex[tokenId];

        if (tokenIndex != lastIndex) {
            uint256 lastTokenId = _ownedTokens[owner][lastIndex];
            _ownedTokens[owner][tokenIndex] = lastTokenId;
            _ownedTokenIndex[lastTokenId]   = tokenIndex;
        }

        _ownedTokens[owner].pop();
        delete _ownedTokenIndex[tokenId];
    }

    function _checkOnERC721Received(
        address from, address to, uint256 tokenId, bytes memory data
    ) internal {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data)
                returns (bytes4 retval)
            {
                if (retval != IERC721Receiver.onERC721Received.selector)
                    revert ERC721ReceiverRejected();
            } catch {
                revert ERC721ReceiverRejected();
            }
        }
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
        emit RoleGranted(role, account);
    }

    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }
        return string(buffer);
    }
}

interface IERC721Receiver {
    function onERC721Received(
        address operator, address from, uint256 tokenId, bytes calldata data
    ) external returns (bytes4);
}
