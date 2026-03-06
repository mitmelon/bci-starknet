#!/usr/bin/env node
/**
 * BCI v1.0 — Starknet Deployment Script
 * Deploys BCIAgentIdentityV1 to Sepolia testnet.
 *
 * PREREQUISITES:
 *   1. Install Scarb:   curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
 *   3. npm install starknet
 *   4. Set env vars below
 *
 * USAGE:
 *   # Deploy (needs compiled Sierra JSON from scarb build):
 *   STARKNET_ACCOUNT=0x... STARKNET_PRIVATE_KEY=0x... node scripts/deploy.js
 *
 */

'use strict';

const fs   = require('fs');
const path = require('path');1

const R = '\x1b[0m';
const ok   = m => console.log(`  \x1b[32m✓\x1b[0m ${m}`);
const info = m => console.log(`  \x1b[36mℹ\x1b[0m ${m}`);
const warn = m => console.log(`  \x1b[33m⚠\x1b[0m ${m}`);
const err  = m => console.log(`  \x1b[31m✗\x1b[0m ${m}`);

console.log('\n\x1b[1m\x1b[36m  BCI v1.0 — Starknet Deploy\x1b[0m\n');
info('Network: Starknet Sepolia Testnet');
info('Contract: BCIAgentIdentityV1.cairo');
console.log('');

async function deploy() {
  // ── Check prerequisites ───────────────────────────────────
  const accountAddress = process.env.STARKNET_ACCOUNT;
  const privateKey     = process.env.STARKNET_PRIVATE_KEY;
  const rpcUrl         = process.env.STARKNET_RPC || 'https://free-rpc.nethermind.io/sepolia-juno';

  if (!accountAddress || !privateKey) {
    warn('Missing env vars. Showing manual deployment steps instead.\n');
    console.log('  \x1b[1mManual deployment (recommended):\x1b[0m\n');
    console.log('  \x1b[2m# 1. Install tools\x1b[0m');
    console.log('  curl --proto \'=https\' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh');
    console.log('  curl https://get.starkli.sh | sh\n');
    console.log('  \x1b[2m# 2. Build Cairo contract\x1b[0m');
    console.log('  scarb build\n');
    console.log('  \x1b[2m# 3. Create Starknet account (if needed)\x1b[0m');
    console.log('  starkli account fetch --network sepolia <YOUR_ADDRESS>\n');
    console.log('  \x1b[2m# 4. Declare contract class\x1b[0m');
    console.log('  starkli declare \\');
    console.log('    target/dev/bci_starknet_BCIAgentIdentityV1.contract_class.json \\');
    console.log('    --network sepolia \\');
    console.log('    --account ~/.starkli-wallets/deployer/account.json \\');
    console.log('    --keystore ~/.starkli-wallets/deployer/keystore.json\n');
    console.log('  \x1b[2m# 5. Deploy contract instance\x1b[0m');
    console.log('  starkli deploy <CLASS_HASH> \\');
    console.log('    --network sepolia \\');
    console.log('    --account ~/.starkli-wallets/deployer/account.json \\');
    console.log('    --keystore ~/.starkli-wallets/deployer/keystore.json\n');
    console.log('  \x1b[2m# 6. Verify on Starkscan\x1b[0m');
    console.log('  https://sepolia.starkscan.co/contract/<CONTRACT_ADDRESS>\n');
    console.log('  \x1b[2m# 7. Update CONTRACT_ADDRESS in scripts/demo.js and run:\x1b[0m');
    console.log('  node scripts/demo.js --testnet\n');
    return;
  }

  // ── Deploy via starknet.js ────────────────────────────────
  let starknet;
  try { starknet = require('starknet'); }
  catch { err('starknet.js not installed — run: npm install starknet'); return; }

  const provider = new starknet.RpcProvider({ nodeUrl: rpcUrl });
  const account  = new starknet.Account(provider, accountAddress, privateKey);

  // Check account balance
  try {
    const block = await provider.getBlockNumber();
    ok(`Connected to Sepolia — block #${block}`);
  } catch (e) {
    err(`Cannot connect to Starknet: ${e.message}`);
    return;
  }

  // Look for compiled contract
  const sierraPath = path.join(__dirname, '..', 'target', 'dev', 'bci_starknet_BCIAgentIdentityV1.contract_class.json');
  const casmPath   = path.join(__dirname, '..', 'target', 'dev', 'bci_starknet_BCIAgentIdentityV1.compiled_contract_class.json');

  if (!fs.existsSync(sierraPath)) {
    warn('Compiled contract not found. Run: scarb build');
    warn(`Expected: ${sierraPath}`);
    return;
  }

  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm   = JSON.parse(fs.readFileSync(casmPath,   'utf8'));

  info('Declaring contract class...');
  try {
    const declareResponse = await account.declare({ contract: sierra, casm });
    await provider.waitForTransaction(declareResponse.transaction_hash);
    ok(`Class declared — hash: ${declareResponse.class_hash}`);

    info('Deploying contract instance...');
    const deployResponse = await account.deployContract({
      classHash: declareResponse.class_hash,
      constructorCalldata: [],
    });
    await provider.waitForTransaction(deployResponse.transaction_hash);
    ok(`Contract deployed!`);
    ok(`Address:  ${deployResponse.contract_address}`);
    ok(`Tx hash:  ${deployResponse.transaction_hash}`);
    ok(`Explorer: https://sepolia.starkscan.co/contract/${deployResponse.contract_address}`);

    // Save deployment info
    const deployInfo = {
      network:          'sepolia',
      contract_address: deployResponse.contract_address,
      class_hash:       declareResponse.class_hash,
      tx_hash:          deployResponse.transaction_hash,
      deployed_at:      new Date().toISOString(),
    };
    fs.writeFileSync(path.join(__dirname, '..', 'deployment.json'), JSON.stringify(deployInfo, null, 2));
    ok(`Deployment info saved to deployment.json`);
    console.log(`\n  \x1b[1mNext step:\x1b[0m node scripts/demo.js --testnet`);
  } catch (e) {
    err(`Deployment failed: ${e.message}`);
    if (e.message.includes('balance')) warn('Make sure your account has Sepolia ETH for gas fees');
  }
}

deploy().catch(e => { console.error('\n  FATAL:', e.message); process.exit(1); });