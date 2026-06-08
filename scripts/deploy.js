import hre from "hardhat";

async function main() {
  const network = hre.network.name;
  console.log(`Deploying to network: ${network}`);
  console.log(`Deployer address: ${(await hre.ethers.getSigners())[0].address}`);

  // 1. Deploy LineageRegistry
  console.log("\n--- Deploying LineageRegistry ---");
  const LineageRegistry = await hre.ethers.getContractFactory("LineageRegistry");
  const registry = await LineageRegistry.deploy();
  await registry.waitForDeployment();
  console.log(`  LineageRegistry deployed at: ${await registry.getAddress()}`);

  // 2. Deploy TrustScorer
  console.log("\n--- Deploying TrustScorer ---");
  const TrustScorer = await hre.ethers.getContractFactory("TrustScorer");
  const scorer = await TrustScorer.deploy();
  await scorer.waitForDeployment();
  const scorerAddress = await scorer.getAddress();
  console.log(`  TrustScorer deployed at: ${scorerAddress}`);

  // 3. Deploy EnforcementLayer
  console.log("\n--- Deploying EnforcementLayer ---");
  const EnforcementLayer = await hre.ethers.getContractFactory("EnforcementLayer");
  const enforcer = await EnforcementLayer.deploy(
    await registry.getAddress(),
    scorerAddress
  );
  await enforcer.waitForDeployment();
  const enforcerAddress = await enforcer.getAddress();
  console.log(`  EnforcementLayer deployed at: ${enforcerAddress}`);

  // 4. Wire enforcer address into TrustScorer
  console.log("\n--- Wiring enforcer into TrustScorer ---");
  const tx = await scorer.setEnforcer(enforcerAddress);
  await tx.wait();
  console.log(`  TrustScorer.enforcer set to: ${enforcerAddress}`);

  // 5. Deploy TargetContract (demo target)
  console.log("\n--- Deploying TargetContract ---");
  const TargetContract = await hre.ethers.getContractFactory("TargetContract");
  const target = await TargetContract.deploy();
  await target.waitForDeployment();
  console.log(`  TargetContract deployed at: ${await target.getAddress()}`);

  // 6. Deploy AgentAccount (ERC-4337 integration)
  const ENTRY_POINT_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"; // canonical ERC-4337 EntryPoint
  console.log("\n--- Deploying AgentAccount ---");
  const AgentAccount = await hre.ethers.getContractFactory("AgentAccount");
  // AgentAccount constructor: (entryPoint, enforcer)
  // Deploy a minimal account for demonstration; in practice each agent deploys its own.
  const account = await AgentAccount.deploy(ENTRY_POINT_ADDRESS, enforcerAddress);
  await account.waitForDeployment();
  console.log(`  AgentAccount deployed at: ${await account.getAddress()}`);

  console.log("\n=== Deployment Summary ===");
  console.log(`LineageRegistry:    ${await registry.getAddress()}`);
  console.log(`TrustScorer:        ${scorerAddress}`);
  console.log(`EnforcementLayer:   ${enforcerAddress}`);
  console.log(`TargetContract:     ${await target.getAddress()}`);
  console.log(`AgentAccount:       ${await account.getAddress()}`);
  console.log(`EntryPoint (fixed): ${ENTRY_POINT_ADDRESS}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
