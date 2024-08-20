import dotenv from 'dotenv';
dotenv.config();

import pkgWeb3Auth from '@web3auth/node-sdk';
const { Web3Auth } = pkgWeb3Auth;
import pkg from '@web3auth/base-provider';
const { CommonPrivateKeyProvider } = pkg;
import jwt from 'jsonwebtoken';
import fs from 'fs';
import bip39 from 'bip39';
import CardanoWasm from '@emurgo/cardano-serialization-lib-nodejs';
import CardanoWallet from 'cardano-wallet-js';
import { C, M, fromHex, toHex } from 'lucid-cardano';

// Load your RSA private key for signing JWT (ensure this is securely stored and loaded)
const privateKey = fs.readFileSync('privateKey.pem');

const clientId = process.env.WEB3AUTH_CLIENT_ID; // Replace with your Web3Auth client ID
const verifier = process.env.WEB3AUTH_VERIFIER; // Your custom verifier name

const user = {
  id: process.env.USER_ID,
  name: process.env.USER_NAME,
  email: process.env.USER_EMAIL,
};

const chainConfig = {
  chainId: '0x1',
  chainNamespace: 'other',
  rpcTarget: 'https://any-rpc-endpoint.com',
};

const cardanoChainConfig = {
  chainNamespace: 'other', // Non-EVM chain
  chainId: '0x1', // Cardano doesn't use EVM's chainId, but you can keep a placeholder
  rpcTarget: 'https://cardano-mainnet.blockfrost.io/api/v0', // Example RPC for Cardano's mainnet using Blockfrost
  displayName: 'Cardano Mainnet',
  blockExplorer: 'https://explorer.cardano.org/en', // Cardano's main block explorer
  ticker: 'ADA',
  tickerName: 'Cardano',
  logo: 'https://cryptologos.cc/logos/cardano-ada-logo.png', // Cardano's logo
};

const cardanoTestnetChainConfig = {
  chainNamespace: 'other', // Non-EVM chain
  chainId: '0x1', // Placeholder as Cardano does not use a chainId like EVM chains
  rpcTarget: 'https://cardano-testnet.blockfrost.io/api/v0', // Example RPC for Cardano's testnet using Blockfrost
  displayName: 'Cardano Testnet',
  blockExplorer: 'https://preprod.cardanoscan.io/', // Cardano's testnet block explorer
  ticker: 'tADA', // Typically 'tADA' to denote testnet ADA
  tickerName: 'Cardano Testnet',
  logo: 'https://cryptologos.cc/logos/cardano-ada-logo.png', // Cardano's logo (same as mainnet for visual consistency)
};

const web3authSfa = new Web3Auth({
  clientId, // Get your Client ID from the Web3Auth Dashboard
  cardanoTestnetChainConfig,
  web3AuthNetwork: 'sapphire_devnet',
  usePnPKey: false, // Setting this to true returns the same key as PnP Web SDK, By default, this SDK returns CoreKitKey.
});

const privateKeyProvider = new CommonPrivateKeyProvider({
  config: { chainConfig: cardanoTestnetChainConfig },
});

web3authSfa.init({ provider: privateKeyProvider });

const token = jwt.sign(
  {
    sub: user.id,
    name: user.name,
    email: user.email,
    aud: process.env.VALIDATION_ENV,
    iss: 'https://raw.githubusercontent.com/Nemanzh/web3auth/main/publicKey.pem',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
  },
  privateKey,
  { algorithm: process.env.ALGORITHM, keyid: process.env.KEY_ID }
);

async function connectAndRequestKey() {
  const web3authSfaprovider = await web3authSfa.connect({
    verifier: verifier, // e.g. `web3auth-sfa-verifier` replace with your verifier name, and it has to be on the same network passed in init().
    verifierId: user.id, // e.g. `Yux1873xnibdui` or `name@email.com` replace with your verifier id(sub or email)'s value.
    idToken: token,
  });

  const key = await web3authSfaprovider.request({
    method: 'private_key',
  });

  // Convert private key to buffer
  const privateKeyBuffer = Buffer.from(key, 'hex');

  // Generate entropy for the mnemonic from the private key
  const entropy1 = privateKeyBuffer.slice(0, 16); // Use the first 16 bytes for entropy

  // Generate mnemonic using bip39
  const mnemonic = bip39.entropyToMnemonic(entropy1.toString('hex'));

  console.log('Private Key:', key);
  console.log('Mnemonic:', mnemonic);

  function harden(num) {
    if (typeof num !== 'number') throw new Error('Type number required here!');
    return 0x80000000 + num;
  }
  const entropy = bip39.mnemonicToEntropy(mnemonic);
  const rootKey = C.Bip32PrivateKey.from_bip39_entropy(
    fromHex(entropy),
    new Uint8Array()
  );

  const accountKey = rootKey
    .derive(harden(1852))
    .derive(harden(1815))
    .derive(harden(0)); //account index

  const pKey = accountKey.derive(0).derive(0).to_raw_key();
  const sKey = accountKey.derive(2).derive(0).to_raw_key();

  const paymentKeyHash = pKey.to_public().hash();
  const stakeKeyHash = sKey.to_public().hash();

  const { address, stakeAddress, paymentAddress } = getAddressesFromKeys(
    pKey,
    sKey,
    'preprod'
  );

  console.log('Address:', address);
  console.log('Stake Address:', stakeAddress);
  console.log('Payment Address:', paymentAddress);

  let message = 'Hello, Cardano!';
  let hexMessage = '';
  for (let i = 0, l = message.length; i < l; i++) {
    hexMessage += message.charCodeAt(i).toString(16);
  }

  const network = CardanoWasm.NetworkInfo.testnet().network_id(); // Testnet (0) or Mainnet (1)
  // const rewardAddress = getRewardAddressFromStakingKey(sKey, network);

  //console.log(rewardAddress, ' rewardAddress');
  let signedMessage = '';
  if (address.startsWith('e0') || address.startsWith('e1')) {
    signedMessage = signDataUtil(paymentAddress, hexMessage, sKey.to_bech32()); //await lucid.wallet.signMessage(rewardAddress, message)
  } else {
    signedMessage = signDataUtil(paymentAddress, hexMessage, pKey.to_bech32()); //await lucid.wallet.signMessage(rewardAddress, message)
  }
  console.log(signedMessage, 'signedMessage');
  console.log(address, 'address');
  console.log(stakeAddress, 'stakeAddress');

  // // Generate a Cardano address using the private key
  // const privateKey = CardanoWasm.PrivateKey.from_normal_bytes(privateKeyBuffer);

  // // Derive public key
  // const publicKey = privateKey.to_public();

  // //Generate a Cardano Base Address (Example for TESTNET)
  // const networkId = CardanoWasm.NetworkInfo.testnet().network_id(); // For TESTNET
  // const baseAddress = CardanoWasm.BaseAddress.new(
  //   networkId,
  //   CardanoWasm.StakeCredential.from_keyhash(publicKey.hash()),
  //   CardanoWasm.StakeCredential.from_keyhash(publicKey.hash())
  // );

  // console.log('Wallet address:', baseAddress.to_address().to_bech32());
}

const getAddressesFromKeys = (paymentKey, stakeKey, network) => {
  const paymentKeyHash = paymentKey.to_public().hash();
  const stakeKeyHash = stakeKey.to_public().hash();

  console.log({ paymentKeyHash, stakeKeyHash });

  const networkId = network === 'Mainnet' ? 1 : 0;
  console.log({ networkId });
  const address = C.BaseAddress.new(
    networkId,
    C.StakeCredential.from_keyhash(paymentKeyHash),
    C.StakeCredential.from_keyhash(stakeKeyHash)
  )
    .to_address()
    .to_bech32();

  console.log({ address });
  const stakeAddr = C.RewardAddress.new(
    networkId,
    C.StakeCredential.from_keyhash(stakeKeyHash)
  )
    .to_address()
    .to_bech32();
  const paymentAddr = C.RewardAddress.new(
    networkId,
    C.StakeCredential.from_keyhash(paymentKeyHash)
  )
    .to_address()
    .to_bech32();

  return { address, stakeAddress: stakeAddr, paymentAddress: paymentAddr };
};

function signDataUtil(addressHex, payload, privateKey) {
  const protectedHeaders = M.HeaderMap.new();
  protectedHeaders.set_algorithm_id(
    M.Label.from_algorithm_id(M.AlgorithmId.EdDSA)
  );
  protectedHeaders.set_header(
    M.Label.new_text('address'),
    M.CBORValue.new_bytes(addressHex)
  );
  const protectedSerialized = M.ProtectedHeaderMap.new(protectedHeaders);
  const unprotectedHeaders = M.HeaderMap.new();
  const headers = M.Headers.new(protectedSerialized, unprotectedHeaders);
  const builder = M.COSESign1Builder.new(headers, fromHex(payload), false);
  const toSign = builder.make_data_to_sign().to_bytes();

  const priv = C.PrivateKey.from_bech32(privateKey);

  const signedSigStruc = priv.sign(toSign).to_bytes();
  const coseSign1 = builder.build(signedSigStruc);

  const key = M.COSEKey.new(
    M.Label.from_key_type(M.KeyType.OKP) //OKP
  );
  key.set_algorithm_id(M.Label.from_algorithm_id(M.AlgorithmId.EdDSA));
  key.set_header(
    M.Label.new_int(M.Int.new_negative(M.BigNum.from_str('1'))),
    M.CBORValue.new_int(
      M.Int.new_i32(6) //M.CurveType.Ed25519
    )
  ); // crv (-1) set to Ed25519 (6)
  key.set_header(
    M.Label.new_int(M.Int.new_negative(M.BigNum.from_str('2'))),
    M.CBORValue.new_bytes(priv.to_public().as_bytes())
  ); // x (-2) set to public key

  return {
    signature: toHex(coseSign1.to_bytes()),
    key: toHex(key.to_bytes()),
  };
}
const utf8ToHex = (str) => {
  return Array.from(str)
    .map((char) => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
};

function getRewardAddressFromStakingKey(stakingKey, networkId) {
  // Convert the staking key to a public key
  const stakingPubKey = stakingKey.to_public();
  const hashPubKey = stakingPubKey.hash();

  console.log(hashPubKey, 'hashPubKey');
  const fromHessh = CardanoWasm.StakeCredential.from_keyhash(hashPubKey);

  // Create the reward address using the staking key's public key
  const rewardAddress = CardanoWasm.RewardAddress.new(
    networkId, // Network ID (0 = testnet, 1 = mainnet)
    fromHessh
  );

  // Convert the reward address to bech32 format (human-readable)
  return rewardAddress.to_address().to_bech32();
}

connectAndRequestKey();
