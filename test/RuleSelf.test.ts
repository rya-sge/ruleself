import { expect } from "chai";
import { deploySystemFixtures } from "../self/contracts/test/utils/deployment";
import { DeployedActors } from "@selfxyz/common/utils/types";
import { ethers } from "hardhat";
import { CIRCUIT_CONSTANTS } from "@selfxyz/contracts/test/constants/constants";
import { ATTESTATION_ID } from "../self/contracts/test/utils/constants";
import { generateVcAndDiscloseProof } from "../self/contracts/test/utils/generateProof";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "@selfxyz/common/utils/passports/passport";
import { generateRandomFieldElement, splitHexFromBack } from "../self/contracts/test/utils/utils";
import { castFromScope } from "@selfxyz/common/utils/circuits/uuid";
import { formatCountriesList, reverseBytes } from "@selfxyz/common/utils/circuits/formatInputs";
import { Formatter } from "../self/contracts/test/utils/formatter";
import { hashEndpointWithScope } from "@selfxyz/common/utils/scope";

describe("ruleSafe", () => {
  let deployedActors: DeployedActors;
  let snapshotId: string;
  let ruleSafe: any;
  let token: any;
  let baseVcAndDiscloseProof: any;
  let vcAndDiscloseProof: any;
  let registerSecret: any;
  let imt: any;
  let commitment: any;
  let nullifier: any;
  let forbiddenCountriesList: any;
  let countriesListPacked: any;
  let attestationIds: any[];

  before(async () => {
    deployedActors = await deploySystemFixtures();
    // must be imported dynamic since @openpassport/zk-kit-lean-imt is exclusively esm and hardhat does not support esm with typescript until verison 3
    const LeanIMT = await import("@openpassport/zk-kit-lean-imt").then((mod) => mod.LeanIMT);
    registerSecret = generateRandomFieldElement();
    nullifier = generateRandomFieldElement();
    attestationIds = [BigInt(ATTESTATION_ID.E_PASSPORT)];
    commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, deployedActors.mockPassport);

    forbiddenCountriesList = ["AAA", "ABC", "CBA"];

    const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
    imt = new LeanIMT<bigint>(hashFunction);
    await imt.insert(BigInt(commitment));

    baseVcAndDiscloseProof = await generateVcAndDiscloseProof(
      registerSecret,
      BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
      deployedActors.mockPassport,
      hashEndpointWithScope("https://test.com", "test-scope"),
      new Array(88).fill("1"),
      "1",
      imt,
      "20",
      undefined,
      undefined,
      undefined,
      undefined,
      forbiddenCountriesList,
      (await deployedActors.user1.getAddress()).slice(2),
    );

    await deployedActors.registry
      .connect(deployedActors.owner)
      .devAddIdentityCommitment(ATTESTATION_ID.E_PASSPORT, nullifier, commitment);

    countriesListPacked = splitHexFromBack(
      reverseBytes(Formatter.bytesToHexString(new Uint8Array(formatCountriesList(forbiddenCountriesList)))),
    );

    const ruleSafeFactory = await ethers.getContractFactory("RuleSafe");
    ruleSafe = await ruleSafeFactory.connect(deployedActors.owner).deploy(
      deployedActors.owner,
      deployedActors.hub.target,
      hashEndpointWithScope("https://test.com", "test-scope"),
      0, // the types show we need a contract version here
      attestationIds,
    );
    await ruleSafe.waitForDeployment();

    const verificationConfig = {
      olderThanEnabled: true,
      olderThan: 20,
      forbiddenCountriesEnabled: true,
      forbiddenCountriesListPacked: countriesListPacked,
      ofacEnabled: [true, true, true] as [boolean, boolean, boolean],
    };
    await ruleSafe.connect(deployedActors.owner).setVerificationConfig(verificationConfig);

    snapshotId = await ethers.provider.send("evm_snapshot", []);
  });

  beforeEach(async () => {
    vcAndDiscloseProof = structuredClone(baseVcAndDiscloseProof);
  });

  afterEach(async () => {
    await ethers.provider.send("evm_revert", [snapshotId]);
    snapshotId = await ethers.provider.send("evm_snapshot", []);
  });

  it("should able to open registration by owner", async () => {
    const { owner } = deployedActors;
    const tx = await ruleSafe.connect(owner).openRegistration();
    const receipt = await tx.wait();
    const event = receipt?.logs.find(
      (log: any) => log.topics[0] === ruleSafe.interface.getEvent("RegistrationOpen").topicHash,
    );
    expect(event).to.not.be.null;
    expect(await ruleSafe.isRegistrationOpen()).to.be.true;
  });

  it("should not able to open registration by non-owner", async () => {
    const { user1 } = deployedActors;
    await expect(ruleSafe.connect(user1).openRegistration())
      .to.be.revertedWithCustomError(ruleSafe, "OwnableUnauthorizedAccount")
      .withArgs(await user1.getAddress());
  });
});