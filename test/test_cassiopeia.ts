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

const abiEncoder = ethers.utils.defaultAbiCoder;

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
    return {
      n,
      t,
      all_keys: result.all_keys,
      cassiopeia: result.cassiopeia,
      timelockInstance: result.timelockInstance,
      preimageInstance: result.preimageInstance,
    };
  };

  const testShareValidSecret = async (
    n: number,
    t: number,
    all_keys: AllKeys,
    instanceContract: Contract,
    cassiopeia: Contract,
    secretID: number,
    witness: any
  ) => {
    const { pvssOutput, receipt } = await shareValidSecret(
      n,
      t,
      all_keys,
      instanceContract,
      cassiopeia
    );
    expect(receipt.events?.length).to.equal(1);

    const reportedSecretID = receipt.events?.at(0)?.args?.secretID;
    expect(reportedSecretID).to.equal(secretID);
    const secret = await cassiopeia.getSecret(secretID);
    expect(secret.instanceVerifier).to.equal(instanceContract.address);
    expect(secret.a_i.length).to.equal(n);
    for (let i = 0; i < n; i++) {
      expect(secret.a_i[i][0]).to.equal(pvssOutput.ciphertext.a_i[i].x);
      expect(secret.a_i[i][1]).to.equal(pvssOutput.ciphertext.a_i[i].y);
    }
    expect(secret.decryptedShares.length).to.equal(0);

    // Try submitting shares but reverted
    const decrypt0 = decryptShare(0, pvssOutput.ciphertext, all_keys.sks[0]);
    await expect(
      cassiopeia.submitShare(1000, 0, decrypt0)
    ).to.be.revertedWith("Secret does not exist");
    await expect(
      cassiopeia.submitShare(secretID, n, decrypt0)
    ).to.be.revertedWith("Index out of bounds");
    await expect(
      cassiopeia.submitShare(secretID, 0, decrypt0)
    ).to.be.revertedWith("Not yet time to submit shares");
    await expect(cassiopeia.claim(secretID, 0)).to.be.revertedWith(
      "Witness invalid"
    );
    if (witness == 0) {
      // NOTE: hack for timelock
      await mineUpTo(await instanceContract.unlockTime());
    }
    await cassiopeia.claim(secretID, witness);
    for (let i = 0; i < t - 1; i++) {
      const decryptedShare = decryptShare(
        i,
        pvssOutput.ciphertext,
        all_keys.sks[i]
      );
      await cassiopeia.submitShare(secretID, i, decryptedShare);
    }
    // TODO: test failure case here
    await cassiopeia.submitShare(
      secretID,
      t - 1,
      decryptShare(t - 1, pvssOutput.ciphertext, all_keys.sks[t - 1])
    );
    // Try to decrypt secret, success!
    expect(
      combineShares(
        convertSharesOnChainToLocal(
          (await cassiopeia.getSecret(secretID)).decryptedShares
        )
      )
    ).to.deep.equal(pvssOutput.secrets.h_f_0);
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
    it("Should pass verification check for valid secret sharing and should only be able to recover if >= t members submit their shares", async () => {
      const { n, t, all_keys, cassiopeia, timelockInstance, preimageInstance } =
        await loadFixture(deployFixture);
      await testShareValidSecret(
        n,
        t,
        all_keys,
        timelockInstance,
        cassiopeia,
        0,
        0,
      );
      await testShareValidSecret(
        n,
        t,
        all_keys,
        preimageInstance,
        cassiopeia,
        1,
        abiEncoder.encode(["string"], ["HI"])
      );
    });
  });
});
