import { execFileSync } from "child_process";
import { ethers } from "hardhat";
import { G2PointStruct } from "../typechain-types/lib/PVSSLib";
import { BigNumber, Contract } from "ethers";
import { defaultAbiCoder, keccak256, sha256 } from "ethers/lib/utils";
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";

const abiEncoder = ethers.utils.defaultAbiCoder;

// eslint-disable-next-line @typescript-eslint/no-redeclare
interface BigInt {
  /** Convert to BigInt to string form in JSON.stringify */
  toJSON: () => string;
}
BigInt.prototype.toJSON = function () {
  return this.toString();
};

const snarkjs = require("snarkjs");

export const ROOT = "/workspace/cassiopeia/zkp/output";
export const PVSS_BIN = "/pvss_target/release/cassiopeia";
export const RAPIDSNARK_BINARY = "/rapidsnark/build/prover";
export const WITNESS_GEN_BIN = join(ROOT, "cassiopeia_cpp/cassiopeia");
export const CIRCUIT_ZKEY = join(ROOT, "keys/cassiopeia_final.zkey");
export const CIRCUIT_VKEY = join(ROOT, "keys/verification_key.json");

export type AllKeys = { sks: [BigNumber]; pks: [G2PointStruct] };

export const deploy = async (n: number, t: number) => {
  const all_keys = genAllKeys(n);
  const PairingLib = await ethers
    .getContractFactory("PairingLib")
    .then((factory) => factory.deploy());
  const PVSSLib = await ethers
    .getContractFactory("PVSSLib", {
      libraries: {
        PairingLib: PairingLib.address,
      },
    })
    .then((factory) => factory.deploy());
  const SNARKVerifier = await ethers
    .getContractFactory("Verifier")
    .then((factory) => factory.deploy());
  const SNARKVerifyLib = await ethers
    .getContractFactory("SNARKVerifyLib")
    .then((factory) => factory.deploy());
  const cassiopeia = await ethers
    .getContractFactory("Cassiopeia", {
      libraries: {
        PVSSLib: PVSSLib.address,
        SNARKVerifyLib: SNARKVerifyLib.address,
      },
    })
    .then((factory) => factory.deploy(t, all_keys.pks, SNARKVerifier.address));

  const timelockInstance = await ethers
    .getContractFactory("TimelockVerifier")
    .then(async (factory) =>
      factory.deploy((await ethers.provider.getBlockNumber()) + 100)
    );
  const preimageInstance = await ethers
    .getContractFactory("SHA256PreimageVerifier")
    .then(async (factory) =>
      factory.deploy(sha256(abiEncoder.encode(["string"], ["HI"])))
    );
  return { all_keys, cassiopeia, timelockInstance, preimageInstance };
};

export const genAllKeys = (n: number): AllKeys =>
  JSON.parse(execFileSync(PVSS_BIN, ["gen-keys", n.toString()]).toString());

export const genValidSecret = (all_keys: AllKeys, t: number) =>
  JSON.parse(
    execFileSync(PVSS_BIN, ["deal-secret", t.toString()], {
      input: JSON.stringify(all_keys.pks),
    }).toString()
  );

export const decryptShare = (i: number, ciphertext: any, sk: any) =>
  JSON.parse(
    execFileSync(PVSS_BIN, ["decrypt-share"], {
      input: JSON.stringify({
        i,
        ciphertext,
        sk,
      }),
    }).toString()
  );

export const combineShares = (shares: any[]) =>
  JSON.parse(
    execFileSync(PVSS_BIN, ["combine-shares"], {
      input: JSON.stringify(shares),
    }).toString()
  );

export const genConcat = (instanceContractAddress: any, pvss_output: any) => {
  const concat = keccak256(
    defaultAbiCoder.encode(
      [
        "address",
        "tuple(tuple(uint256 x, uint256 y)[] f_i, tuple(uint256 x, uint256 y)[] a_i, tuple(uint256[2] x, uint256[2] y)[] y_i)",
      ],
      [instanceContractAddress, pvss_output.ciphertext]
    )
  );
  const concatHalves = ["0x" + concat.slice(2, 34), "0x" + concat.slice(34)];
  return concatHalves;
};

export const genSNARKVerifierCall = async (
  pvss_output: any,
  concatHalves: string[]
) => {
  // Generate SNARK circuit outputs
  const input = {
    secret: BigInt(pvss_output.secrets.f_0),
    concat: [BigInt(concatHalves[0]), BigInt(concatHalves[1])],
  };
  writeFileSync("/tmp/input.json", JSON.stringify(input));
  execFileSync(WITNESS_GEN_BIN, ["/tmp/input.json", "/tmp/witness.wtns"]);
  execFileSync(RAPIDSNARK_BINARY, [
    CIRCUIT_ZKEY,
    "/tmp/witness.wtns",
    "/tmp/proof.json",
    "/tmp/public.json",
  ]);
  const proof = JSON.parse(readFileSync("/tmp/proof.json").toString());
  const publicSignals = JSON.parse(readFileSync("/tmp/public.json").toString());

  const vKey = JSON.parse(readFileSync(CIRCUIT_VKEY).toString());
  if (!(await snarkjs.groth16.verify(vKey, publicSignals, proof))) {
    throw new Error("Local verification did not pass");
  }

  const calldataRaw = await snarkjs.groth16.exportSolidityCallData(
    proof,
    publicSignals
  );
  const calldata = JSON.parse("[" + calldataRaw + "]");
  const proofCalldata = {
    a: calldata[0],
    b: calldata[1],
    c: calldata[2],
  };
  const H = calldata[3][0];
  return { H, proofCalldata };
};

export const shareValidSecret = async (
  n: number,
  t: number,
  all_keys: AllKeys,
  instanceContract: Contract,
  cassiopeia: Contract
) => {
  const pvssOutput = genValidSecret(all_keys, t);
  const concatHalves = genConcat(instanceContract.address, pvssOutput);
  const { H, proofCalldata } = await genSNARKVerifierCall(
    pvssOutput,
    concatHalves
  );

  const receipt = await (
    await cassiopeia.shareSecret(
      instanceContract.address,
      pvssOutput.ciphertext,
      H,
      proofCalldata
    )
  ).wait();

  return {
    pvssOutput,
    concatHalves,
    H,
    proofCalldata,
    receipt,
  };
};
