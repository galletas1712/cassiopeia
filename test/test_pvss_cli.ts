import { execFileSync } from "child_process";
import { expect } from "chai";
import { shuffled } from "ethers/lib/utils";

const BINARY = "pvss/target/debug/cassiopeia";

describe("PVSS CLI", () => {
  const testRunEndToEnd = (n: number, t: number) => {
    const all_keys = JSON.parse(
      execFileSync(BINARY, ["gen-keys", n.toString()]).toString()
    );
    const pvss_output = JSON.parse(
      execFileSync(BINARY, ["deal-secret", t.toString()], {
        input: JSON.stringify(all_keys.pks),
      }).toString()
    );
    let indices = shuffled([...Array(n).keys()]);
    const decryptedShares = indices.map((i) => [
      i,
      JSON.parse(
        execFileSync(BINARY, ["decrypt-share"], {
          input: JSON.stringify({
            i: i,
            ciphertext: pvss_output.ciphertext,
            sk: all_keys.sks[i],
          }),
        }).toString()
      ),
    ]);
    for (let numRevealed = 0; numRevealed <= n; numRevealed++) {
      const decryptedSecret = JSON.parse(
        execFileSync(BINARY, ["combine-shares"], {
          input: JSON.stringify(decryptedShares.slice(0, numRevealed)),
        }).toString()
      );
      if (numRevealed < t) {
        expect(decryptedSecret).to.not.deep.equal(pvss_output.secrets.h_f_0);
      } else {
        expect(decryptedSecret).to.deep.equal(pvss_output.secrets.h_f_0);
      }
    }
  };

  it("Should recover a valid secret if and only if number of revealed shares >= t", () => {
    const n = Math.floor(Math.random() * 25) + 1;
    const t = Math.floor(Math.random() * n) + 1; // Between 1 and n inclusive
    testRunEndToEnd(n, t);
  });
});
