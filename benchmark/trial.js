// import { deploy, shareValidSecret } from "../cassiopeia_lib";

module.exports = async ({n, t}) => {
  const { all_keys, cassiopeia } = await deploy(n, t);
  const gas1 = (await shareValidSecret(n, t, all_keys, cassiopeia)).receipt.gasUsed.toString();
  const gas2 = (await shareValidSecret(n, t, all_keys, cassiopeia)).receipt.gasUsed.toString();
  return { gas1, gas2 };
};
