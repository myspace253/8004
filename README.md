# 8004

ERC8004 smart contracts for Base mainnet.

## Contracts

- `ERC8004Token.sol`: ERC20 token with fees and permit
- `ERC8004ServiceNFT.sol`: ERC721 NFT with tier system
- `ERC8004Core.sol`: Business logic for subscriptions and upgrades
- `SecureVault.sol`: Vault for secure token storage

## Deployment

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create `.env` file with your keys:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your `PRIVATE_KEY` and `BASESCAN_API_KEY`.

3. Deploy to Base mainnet:
   ```bash
   npm run deploy
   ```

4. Verify contracts on Basescan:
   ```bash
   npm run verify
   ```

## Requirements

- Node.js
- Hardhat
- Private key with ETH on Base mainnet
- Basescan API key