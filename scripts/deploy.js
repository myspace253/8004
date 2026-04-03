import { ethers } from "hardhat";
import fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  // Deploy ERC8004Token
  const ERC8004Token = await ethers.getContractFactory("ERC8004Token");
  const token = await ERC8004Token.deploy(
    "ERC8004 Token", // name
    "ERC8004", // symbol
    0, // maxSupply (0 = unlimited)
    ethers.parseEther("1000000"), // initialSupply (1M tokens)
    deployer.address, // treasury
    100 // feeBps (1%)
  );
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log("ERC8004Token deployed to:", tokenAddress);

  // Deploy ERC8004ServiceNFT
  const ERC8004ServiceNFT = await ethers.getContractFactory("ERC8004ServiceNFT");
  const nft = await ERC8004ServiceNFT.deploy();
  await nft.waitForDeployment();
  const nftAddress = await nft.getAddress();
  console.log("ERC8004ServiceNFT deployed to:", nftAddress);

  // Deploy ERC8004Core
  const ERC8004Core = await ethers.getContractFactory("ERC8004Core");
  const core = await ERC8004Core.deploy(
    tokenAddress,
    nftAddress,
    deployer.address // treasury
  );
  await core.waitForDeployment();
  const coreAddress = await core.getAddress();
  console.log("ERC8004Core deployed to:", coreAddress);

  // Deploy SecureVault
  const SecureVault = await ethers.getContractFactory("SecureVault");
  const vault = await SecureVault.deploy(deployer.address);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log("SecureVault deployed to:", vaultAddress);

  // Set tier prices in Core (example prices)
  await core.setTierPrice(0, ethers.parseEther("100")); // BASIC: 100 tokens
  await core.setTierPrice(1, ethers.parseEther("500")); // PRO: 500 tokens
  await core.setTierPrice(2, ethers.parseEther("2000")); // ELITE: 2000 tokens
  await core.setTierPrice(3, ethers.parseEther("10000")); // GENESIS: 10000 tokens
  console.log("Tier prices set");

  // Grant MINTER_ROLE to Core in NFT
  const MINTER_ROLE = await nft.MINTER_ROLE();
  await nft.grantRole(MINTER_ROLE, coreAddress);
  console.log("Granted MINTER_ROLE to Core");

  console.log("All contracts deployed and configured!");
  const addresses = {
    token: tokenAddress,
    nft: nftAddress,
    core: coreAddress,
    vault: vaultAddress,
    treasury: deployer.address,
  };
  console.log(addresses);

  // Save addresses to file
  fs.writeFileSync("deployed-addresses.json", JSON.stringify(addresses, null, 2));
  console.log("Addresses saved to deployed-addresses.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });