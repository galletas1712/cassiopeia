import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import { Contract } from "ethers";
import { AllKeys, shareValidSecret, deploy } from "../cassiopeia_lib";

describe("Cassiopeia", () => {
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
    const { pvssOutput, unlockTime, receipt} = await shareValidSecret(n, t, all_keys, cassiopeia);
    expect(receipt.events?.length).to.equal(1);

    const reportedSecretID = receipt.events?.at(0)?.args?.secretID;
    expect(reportedSecretID).to.equal(secretID);
    const secret = await cassiopeia.getSecret(secretID);
    expect(secret.unlockTime).to.equal(unlockTime);
    expect(secret.a_i.length).to.equal(n);
    for (let i = 0; i < n; i++) {
      expect(secret.a_i[i][0]).to.equal(pvssOutput.ciphertext.a_i[i].x);
      expect(secret.a_i[i][1]).to.equal(pvssOutput.ciphertext.a_i[i].y);
    }
    expect(secret.decryptedShares.length).to.equal(0);
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
});
