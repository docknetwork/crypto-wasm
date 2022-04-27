import {benchmark, report} from "@stablelib/benchmark";
import {
    boundCheckSnarkSetup, generateBBSPublicKeyG2, generateBBSSigningKey,
    generateSignatureParamsG1,
    initializeWasm,
    legosnarkDecompressPk,
    legosnarkVkFromPk
} from "../lib";

export const benchmarkBoundCheckSnark = async (
): Promise<void> => {
    await initializeWasm();

    report(
        'Bound check snark setup',
        benchmark(() => boundCheckSnarkSetup(false))
    );
    const snarkPk = boundCheckSnarkSetup(false);

    report(
        'Decompress legosnark proving key',
        benchmark(() => legosnarkDecompressPk(snarkPk))
    );
    const snarkPkDecom = legosnarkDecompressPk(snarkPk);

    report(
        'Get uncompressed legosnark verifying key',
        benchmark(() => legosnarkVkFromPk(snarkPk, true))
    );
    report(
        'Get compressed legosnark verifying key',
        benchmark(() => legosnarkVkFromPk(snarkPk, false))
    );
    const snarkVkDecom = legosnarkVkFromPk(snarkPk, true);

    const sigParams = generateSignatureParamsG1(1);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);
};
