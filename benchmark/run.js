const fs = require("fs");
const path = require("path");
const Piscina = require("piscina");

const piscina = new Piscina({
  filename: path.resolve(__dirname, "trial.js"),
});

const stream = fs.createWriteStream("benchmark.txt");

(async function () {
  let promises = [];
  for (let n = 1; n <= 2; n++) {
    for (let t of [1, Math.floor(n / 2) + 1, n]) {
      if (t > n) continue;
      promises.push(
        piscina.run({ n, t }).then((result) => {
          const { gas1, gas2 } = result;
          const result1 = `${n},${t},${gas1}`;
          const result2 = `${n},${t},${gas2}`;
          console.log(result1);
          console.log(result2);
          stream.write(result1 + "\n");
          stream.write(result2 + "\n");
        })
      );
    }
  }
  await Promise.all(promises);
  stream.end();
})();
