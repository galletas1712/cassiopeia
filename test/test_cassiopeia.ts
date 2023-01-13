import {
  loadFixture,
  mineUpTo,
} from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { expect, util } from "chai";
import { Contract } from "ethers";
import {
  AllKeys,
  shareValidSecret,
  deploy,
  decryptShare,
  combineShares,
} from "./cassiopeia_lib";

const convertSharesOnChainToLocal = (decryptedShares: any) =>
  decryptedShares.map((obj: any) => [
    obj.i.toNumber(),
    {
      x: [obj.share.x[0].toHexString(), obj.share.x[1].toHexString()],
      y: [obj.share.y[0].toHexString(), obj.share.y[1].toHexString()],
    },
  ]);

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
    const { pvssOutput, unlockTime, receipt } = await shareValidSecret(
      n,
      t,
      all_keys,
      cassiopeia
    );
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
  });

  describe("Secret sharing", () => {
    it("Should pass verification check for valid secret sharing", async () => {
      const { n, t, all_keys, cassiopeia } = await loadFixture(deployFixture);
      await testShareValidSecret(n, t, all_keys, cassiopeia, 0);
      await testShareValidSecret(n, t, all_keys, cassiopeia, 1);
    });

    it("Should be able to recover secret if >= t members submit their shares and not otherwise", async () => {
      const { n, t, all_keys, cassiopeia } = await loadFixture(deployFixture);
      const { pvssOutput, unlockTime } = await shareValidSecret(
        n,
        t,
        all_keys,
        cassiopeia
      );
      // Try submitting shares but reverted
      const decrypt0 = decryptShare(0, pvssOutput.ciphertext, all_keys.sks[0]);
      await expect(cassiopeia.submitShare(100, 0, decrypt0)).to.be.revertedWith(
        "Secret does not exist"
      );
      await expect(cassiopeia.submitShare(0, n, decrypt0)).to.be.revertedWith(
        "Index out of bounds"
      );
      await expect(cassiopeia.submitShare(0, 0, decrypt0)).to.be.revertedWith(
        "Not yet time to submit shares"
      );
      await mineUpTo(unlockTime);
      for (let i = 0; i < t - 1; i++) {
        const decryptedShare = decryptShare(
          i,
          pvssOutput.ciphertext,
          all_keys.sks[i]
        );
        await cassiopeia.submitShare(0, i, decryptedShare);
      }
      // Try to decrypt secret, fail to do so
      expect(
        combineShares(
          convertSharesOnChainToLocal(
            (await cassiopeia.getSecret(0)).decryptedShares
          )
        )
      ).to.not.deep.equal(pvssOutput.secrets.h_f_0);
      await cassiopeia.submitShare(
        0,
        t - 1,
        decryptShare(t - 1, pvssOutput.ciphertext, all_keys.sks[t - 1])
      );
      // Try to decrypt secret, success!
      expect(
        combineShares(
          convertSharesOnChainToLocal(
            (await cassiopeia.getSecret(0)).decryptedShares
          )
        )
      ).to.deep.equal(pvssOutput.secrets.h_f_0);
    });
  });
});
