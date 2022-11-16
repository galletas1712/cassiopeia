import { execFileSync } from "child_process";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import { G2PointStruct } from "../typechain-types/lib/PVSSLib";
import { BigNumber, Contract } from "ethers";
import { defaultAbiCoder, keccak256 } from "ethers/lib/utils";
import { readFileSync, writeFileSync } from "fs";

const snarkjs = require("snarkjs");
const wc = require("../zkp/output/cassiopeia_js/witness_calculator");

const BINARY = "pvss/target/debug/cassiopeia";
const CIRCUIT_WASM = "zkp/output/cassiopeia_js/cassiopeia.wasm";
const CIRCUIT_ZKEY = "zkp/output/keys/cassiopeia_final.zkey";
const CIRCUIT_VKEY = "zkp/output/keys/verification_key.json";

type AllKeys = { sks: [BigNumber]; pks: [G2PointStruct] };

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
  unlockTime: any,
  pvss_output: any,
  concatHalves: string[]
) => {
  // Generate SNARK circuit outputs
  const input = {
    secret: BigInt(pvss_output.secrets.f_0),
    concat: [BigInt(concatHalves[0]), BigInt(concatHalves[1])],
  };
  await wc(readFileSync(CIRCUIT_WASM)).then(async (witnessCalculator: any) => {
    const buff = await witnessCalculator.calculateWTNSBin(input, 0);
    writeFileSync("/tmp/witness.wtns", buff);
  });
  const { proof, publicSignals } = await snarkjs.plonk.prove(
    CIRCUIT_ZKEY,
    "/tmp/witness.wtns"
  );
  const calldata: string = await snarkjs.plonk.exportSolidityCallData(
    proof,
    publicSignals
  );
  const proofCalldata = calldata.slice(0, calldata.indexOf(","));
  const pubSignalsCalldata = JSON.parse(
    calldata.slice(calldata.indexOf(",") + 1)
  );
  return {
    proof,
    pubSignals: publicSignals,
    proofCalldata,
    pubSignalsCalldata,
  };
};

describe("Cassiopeia", () => {
  const n = Math.floor(Math.random() * 25) + 1;
  const t = Math.floor(Math.random() * n) + 1; // Between 1 and n inclusive

  const deployFixture = async () => {
    const all_keys: AllKeys = JSON.parse(
      execFileSync(BINARY, ["gen-keys", n.toString()]).toString()
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
    const PlonkVerifier = await ethers
      .getContractFactory("PlonkVerifier")
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
      .then((factory) =>
        factory.deploy(t, all_keys.pks, PlonkVerifier.address)
      );
    return { all_keys, cassiopeia: Cassiopeia };
  };

  describe("Deployment", () => {
    it("Should set the right parameters at initialization", async () => {
      const { all_keys, cassiopeia } = await loadFixture(deployFixture);
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
    const genValidSecret = (all_keys: AllKeys) =>
      JSON.parse(
        execFileSync(BINARY, ["deal-secret", t.toString()], {
          input: JSON.stringify(all_keys.pks),
        }).toString()
      );

    const testShareValidSecret = async (
      all_keys: AllKeys,
      cassiopeia: Contract,
      secretID: number
    ) => {
      const pvss_output = genValidSecret(all_keys);
      const unlockTime = BigNumber.from(ethers.utils.randomBytes(32));
      const concatHalves = genConcat(unlockTime, pvss_output);

      const { proof, pubSignals, proofCalldata, pubSignalsCalldata } =
        await genSNARKVerifierCall(unlockTime, pvss_output, concatHalves);
      const vKey = JSON.parse(readFileSync(CIRCUIT_VKEY).toString());
      expect(await snarkjs.plonk.verify(vKey, pubSignals, proof)).to.be.true;

      const receipt = await (
          await cassiopeia.shareSecret(
            unlockTime,
            pvss_output.ciphertext,
            {
              hashCmt: pubSignalsCalldata[0],
              babyJubCmt: [pubSignalsCalldata[1], pubSignalsCalldata[2]],
            },
            proofCalldata,
          )
        ).wait()
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

      console.log("Size of committee:", n);
      console.log("Gas used:", receipt.gasUsed.toString())
    };

    it("Should pass verification check for valid secret sharing", async () => {
      const { all_keys, cassiopeia } = await loadFixture(deployFixture);
      await testShareValidSecret(all_keys, cassiopeia, 0);
      await testShareValidSecret(all_keys, cassiopeia, 1);
      await testShareValidSecret(all_keys, cassiopeia, 2);
    });
  });
});
