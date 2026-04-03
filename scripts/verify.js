import { run } from "hardhat";
import { ethers } from "hardhat";
import fs from "fs";

async function main() {
  const addresses = JSON.parse(fs.readFileSync("deployed-addresses.json", "utf8"));
  console.log("Loaded addresses:", addresses);

  console.log("Verifying ERC8004Token...");
  try {
    await run("verify:verify", {
      address: addresses.token,
      constructorArguments: [
        "ERC8004 Token",
        "ERC8004",
        0,
        ethers.parseEther("1000000"),
        addresses.treasury,
        100
      ],
    });
    console.log("ERC8004Token verified!");
  } catch (error) {
    console.error("ERC8004Token verification failed:", error.message);
  }

  console.log("Verifying ERC8004ServiceNFT...");
  try {
    await run("verify:verify", {
      address: addresses.nft,
      constructorArguments: [],
    });
    console.log("ERC8004ServiceNFT verified!");
  } catch (error) {
    console.error("ERC8004ServiceNFT verification failed:", error.message);
  }

  console.log("Verifying ERC8004Core...");
  try {
    await run("verify:verify", {
      address: addresses.core,
      constructorArguments: [
        addresses.token,
        addresses.nft,
        addresses.treasury
      ],
    });
    console.log("ERC8004Core verified!");
  } catch (error) {
    console.error("ERC8004Core verification failed:", error.message);
  }

  console.log("Verifying SecureVault...");
  try {
    await run("verify:verify", {
      address: addresses.vault,
      constructorArguments: [
        addresses.treasury
      ],
    });
    console.log("SecureVault verified!");
  } catch (error) {
    console.error("SecureVault verification failed:", error.message);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });