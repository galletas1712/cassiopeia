import { execFileSync } from "child_process";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import { G2PointStruct } from "../typechain-types/lib/PVSSLib";
import { BigNumber, Contract } from "ethers";
import { defaultAbiCoder, keccak256 } from "ethers/lib/utils";
import { createWriteStream, readFileSync, writeFileSync } from "fs";
import { join } from "path";

// eslint-disable-next-line @typescript-eslint/no-redeclare
interface BigInt {
  /** Convert to BigInt to string form in JSON.stringify */
  toJSON: () => string;
}
BigInt.prototype.toJSON = function () {
  return this.toString();
};

const snarkjs = require("snarkjs");

const ROOT = "zkp/output";
const PVSS_BIN = "pvss/target/debug/cassiopeia";
const RAPIDSNARK_BINARY = "../rapidsnark/build/prover"
const WITNESS_GEN_BIN = join(ROOT, "cassiopeia_cpp/cassiopeia");
const CIRCUIT_ZKEY = join(ROOT, "keys/cassiopeia_final.zkey");
const CIRCUIT_VKEY = join(ROOT, "keys/verification_key.json");

type AllKeys = { sks: [BigNumber]; pks: [G2PointStruct] };

const deploy = async (n: number, t: number) => {
  const all_keys: AllKeys = JSON.parse(
    execFileSync(PVSS_BIN, ["gen-keys", n.toString()]).toString()
  );
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
  const Cassiopeia = await ethers
    .getContractFactory("Cassiopeia", {
      libraries: {
        PVSSLib: PVSSLib.address,
        SNARKVerifyLib: SNARKVerifyLib.address,
      },
    })
    .then((factory) => factory.deploy(t, all_keys.pks, SNARKVerifier.address));
  return { all_keys, cassiopeia: Cassiopeia };
};

const genConcat = (unlockTime: any, pvss_output: any) => {
  const concat = keccak256(
    defaultAbiCoder.encode(
      [
        "uint256",
        "tuple(tuple(uint256 x, uint256 y)[] f_i, tuple(uint256 x, uint256 y)[] a_i, tuple(uint256[2] x, uint256[2] y)[] y_i)",
      ],
      [unlockTime, pvss_output.ciphertext]
    )
  );
  const concatHalves = ["0x" + concat.slice(2, 34), "0x" + concat.slice(34)];
  return concatHalves;
};

const genSNARKVerifierCall = async (
  pvss_output: any,
  concatHalves: string[]
) => {
  // Generate SNARK circuit outputs
  const input = {
    secret: BigInt(pvss_output.secrets.f_0),
    concat: [BigInt(concatHalves[0]), BigInt(concatHalves[1])],
  };
  writeFileSync("/tmp/input.json", JSON.stringify(input));
  execFileSync(WITNESS_GEN_BIN, [
    "/tmp/input.json",
    "/tmp/witness.wtns",
  ]);
  execFileSync(RAPIDSNARK_BINARY, [
    CIRCUIT_ZKEY,
    "/tmp/witness.wtns",
    "/tmp/proof.json",
    "/tmp/public.json",
  ]);
  const proof = JSON.parse(readFileSync("/tmp/proof.json").toString());
  const publicSignals = JSON.parse(readFileSync("/tmp/public.json").toString());

  const vKey = JSON.parse(readFileSync(CIRCUIT_VKEY).toString());
  expect(await snarkjs.groth16.verify(vKey, publicSignals, proof)).to.be.true;

  const calldataRaw = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const calldata = JSON.parse("[" + calldataRaw + "]");
  const proofCalldata = {
    a: calldata[0],
    b: calldata[1],
    c: calldata[2]
  }
  const H = calldata[3][0];
  return { H, proofCalldata };
};

describe("Cassiopeia", () => {
  const genValidSecret = (all_keys: AllKeys, t: number) =>
    JSON.parse(
      execFileSync(PVSS_BIN, ["deal-secret", t.toString()], {
        input: JSON.stringify(all_keys.pks),
      }).toString()
    );

  const deployFixture = async () => {
    const n = Math.floor(Math.random() * 25) + 1;
    const t = Math.floor(Math.random() * n) + 1; // Between 1 and n inclusive

    const result = await deploy(n, t);
    return { n, t, all_keys: result.all_keys, cassiopeia: result.cassiopeia };
  };

  const testShareValidSecret = async (
    n: number,
    t: number,
    all_keys: AllKeys,
    cassiopeia: Contract,
    secretID: number
  ) => {
    const pvss_output = genValidSecret(all_keys, t);
    const unlockTime = BigNumber.from(ethers.utils.randomBytes(32));
    const concatHalves = genConcat(unlockTime, pvss_output);

    const { H, proofCalldata } = await genSNARKVerifierCall(pvss_output, concatHalves);

    const receipt = await (
      await cassiopeia.shareSecret(
        unlockTime,
        pvss_output.ciphertext,
        H,
        proofCalldata
      )
    ).wait();
    expect(receipt.events?.length).to.equal(1);

    const reportedSecretID = receipt.events?.at(0)?.args?.secretID;
    expect(reportedSecretID).to.equal(secretID);
    const secret = await cassiopeia.getSecret(secretID);
    expect(secret.unlockTime).to.equal(unlockTime);
    expect(secret.a_i.length).to.equal(n);
    for (let i = 0; i < n; i++) {
      expect(secret.a_i[i][0]).to.equal(pvss_output.ciphertext.a_i[i].x);
      expect(secret.a_i[i][1]).to.equal(pvss_output.ciphertext.a_i[i].y);
    }
    expect(secret.decryptedShares.length).to.equal(0);

    return receipt.gasUsed.toString();
  };

  describe("Deployment", () => {
    it("Should set the right parameters at initialization", async () => {
      const { n, t, all_keys, cassiopeia } = await loadFixture(deployFixture);
      expect(await cassiopeia.n()).to.equal(n);
      expect(await cassiopeia.t()).to.equal(t);
      for (let i = 0; i < n; i++) {
        const pk = await cassiopeia.getPK(i);
        expect(pk.x[0]).to.equal(all_keys.pks[i].x[0]);
        expect(pk.x[1]).to.equal(all_keys.pks[i].x[1]);
        expect(pk.y[0]).to.equal(all_keys.pks[i].y[0]);
        expect(pk.y[1]).to.equal(all_keys.pks[i].y[1]);
      }
    });
    // TODO: test fail deploy
  });

  describe("Secret sharing", () => {
    it("Should pass verification check for valid secret sharing", async () => {
      const { n, t, all_keys, cassiopeia } = await loadFixture(deployFixture);
      await testShareValidSecret(n, t, all_keys, cassiopeia, 0);
      await testShareValidSecret(n, t, all_keys, cassiopeia, 1);
    });
  });

  describe("Benchmark", () => {
    for (let n = 1; n <= 53; n++) {
      for (let t of [1, Math.floor(n / 2) + 1, n]) {
        if (t > n) continue;
        it(`Should work on n = ${n}, t = ${t}`, async () => {
          const { all_keys, cassiopeia } = await deploy(n, t);
          const gas1 = await testShareValidSecret(
            n,
            t,
            all_keys,
            cassiopeia,
            0
          );
          console.log(`${n},${t},${gas1}\n`);
          const gas2 = await testShareValidSecret(
            n,
            t,
            all_keys,
            cassiopeia,
            1
          );
          console.log(`${n},${t},${gas2}\n`);
        });
      }
    }
  });
});
