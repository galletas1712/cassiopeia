import { execFileSync } from "child_process";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import { G2PointStruct } from "../typechain-types/Cassiopeia.sol/Cassiopeia";
import { BigNumber, Contract } from "ethers";

const BINARY = "pvss/target/debug/cassiopeia";

type AllKeys = { sks: [BigNumber]; pks: [G2PointStruct] };

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
    const cassiopeia = await ethers
      .getContractFactory("Cassiopeia", {
        libraries: {
          PVSSLib: PVSSLib.address,
        },
      })
      .then((factory) => factory.deploy(t, all_keys.pks));
    return { all_keys, cassiopeia };
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
      const events = (
        await (
          await cassiopeia.shareSecret(unlockTime, pvss_output.ciphertext)
        ).wait()
      ).events;
      expect(events?.length).to.equal(1);
      const reportedSecretID = events?.at(0)?.args?.secretID;
      expect(reportedSecretID).to.equal(secretID);
      const secret = await cassiopeia.getSecret(secretID);
      expect(secret.unlockTime).to.equal(unlockTime);
      expect(secret.a_i.length).to.equal(n);
      for (let i = 0; i < n; i++) {
        expect(secret.a_i[i][0]).to.equal(pvss_output.ciphertext.a_i[i].x);
        expect(secret.a_i[i][1]).to.equal(pvss_output.ciphertext.a_i[i].y);
      }
      expect(secret.decryptedShares.length).to.equal(0);
    };

    it("Should pass verification check for valid secret sharing", async () => {
      const { all_keys, cassiopeia } = await loadFixture(deployFixture);
      await testShareValidSecret(all_keys, cassiopeia, 0);
      await testShareValidSecret(all_keys, cassiopeia, 1);
      await testShareValidSecret(all_keys, cassiopeia, 2);
    });
  });
});
