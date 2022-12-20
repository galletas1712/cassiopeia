import { execFileSync } from "child_process";
import { expect } from "chai";
import { shuffled, randomBytes, hexlify } from "ethers/lib/utils";

const BINARY = "pvss/target/debug/cassiopeia";

describe("PVSS CLI", () => {
  const setup = (n: number, t: number) => {
    const allKeys = JSON.parse(
      execFileSync(BINARY, ["gen-keys", n.toString()]).toString()
    );
    const pvssOutput = JSON.parse(
      execFileSync(BINARY, ["deal-secret", t.toString()], {
        input: JSON.stringify(allKeys.pks),
      }).toString()
    );
    let indices = shuffled([...Array(n).keys()]);
    const decryptedShares = indices.map((i) => [
      i,
      JSON.parse(
        execFileSync(BINARY, ["decrypt-share"], {
          input: JSON.stringify({
            i: i,
            ciphertext: pvssOutput.ciphertext,
            sk: allKeys.sks[i],
          }),
        }).toString()
      ),
    ]);
		return { allKeys, pvssOutput, decryptedShares };
  }

	const decryptSecret = (decryptedShares: any[]) => JSON.parse(
		execFileSync(BINARY, ["combine-shares"], {
			input: JSON.stringify(decryptedShares),
		}).toString()
	);

  it("Should recover a valid secret if and only if number of revealed shares >= t", () => {
    const n = Math.floor(Math.random() * 25) + 1;
    const t = Math.floor(Math.random() * n) + 1; // Between 1 and n inclusive
		const { allKeys, pvssOutput, decryptedShares } = setup(n, t);
    for (let numRevealed = 0; numRevealed <= n; numRevealed++) {
			const decryptedSecret = decryptSecret(decryptedShares.slice(0, numRevealed));
      if (numRevealed < t) {
        expect(decryptedSecret).to.not.deep.equal(pvssOutput.secrets.h_f_0);
      } else {
        expect(decryptedSecret).to.deep.equal(pvssOutput.secrets.h_f_0);
      }
    }
  });

	it("Should print out different result if at least one invalid share incorporated", () => {
    const n = Math.floor(Math.random() * 23) + 3;
		const { allKeys, pvssOutput, decryptedShares } = setup(n, n - 1);

		expect(decryptSecret(decryptedShares)).to.deep.equal(pvssOutput.secrets.h_f_0);
		expect(decryptSecret(decryptedShares.slice(0, n - 1))).to.deep.equal(pvssOutput.secrets.h_f_0);
		expect(decryptSecret(decryptedShares.slice(0, n - 2))).to.not.deep.equal(pvssOutput.secrets.h_f_0);

		const randBytes = randomBytes(32);
		const sub = hexlify([0, ...randBytes.slice(1)]);
		const newDecryptedShares = [...decryptedShares.slice(0, n - 1),
			[
				decryptedShares[n - 1][0],
				{
					x: [sub, sub],
					y: [sub, sub],
				}
			]
		];
		expect(decryptSecret(newDecryptedShares)).to.not.deep.equal(pvssOutput.secrets.h_f_0);
	});
});
