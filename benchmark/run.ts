import { createWriteStream } from "fs";
import { deploy, shareValidSecret } from "../cassiopeia_lib";

(async function () {
  const stream = createWriteStream("benchmark.txt");
  for (let n = 1; n <= 100; n++) {
    for (let t of [1, Math.floor(n / 2) + 1, n]) {
      if (t > n) continue;
      const { all_keys, cassiopeia } = await deploy(n, t);
      const gas1 = (await shareValidSecret(n, t, all_keys, cassiopeia)).receipt.gasUsed.toString();
      const gas2 = (await shareValidSecret(n, t, all_keys, cassiopeia)).receipt.gasUsed.toString();
      const result1 = `${n},${t},${gas1}`;
      const result2 = `${n},${t},${gas2}`;
      console.log(result1);
      console.log(result2);
      stream.write(result1 + "\n");
      stream.write(result2 + "\n");
    }
  }
  stream.end();
})();
