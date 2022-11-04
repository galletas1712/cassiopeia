import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.17",
  networks: {
    hardhat: {
      hardfork: "merge",
      allowUnlimitedContractSize: true
    }
  }
};

export default config;
