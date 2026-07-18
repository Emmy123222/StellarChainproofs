import { expect } from "chai";
import { ethers } from "hardhat";

describe("VulnerableToken", function () {
  it("deploys and accepts deposits", async function () {
    const Token = await ethers.getContractFactory("VulnerableToken");
    const token = await Token.deploy();
    await token.waitForDeployment();

    const [user] = await ethers.getSigners();
    await token.connect(user).deposit({ value: ethers.parseEther("1") });

    expect(await token.balances(user.address)).to.equal(ethers.parseEther("1"));
  });
});
