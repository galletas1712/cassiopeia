import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [{ version: "0.8.17" }, { version: "0.6.11" }],
  },
  networks: {
    hardhat: {
      hardfork: "merge",
      allowUnlimitedContractSize: true,
    },
  },
  mocha: {
    timeout: 60000000,
  },
};

export default config;
