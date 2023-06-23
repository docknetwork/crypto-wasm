import {BbsPlusSigParams, BbsSigParams} from "../types";

export function generateGadgetVectorForThresholdSig(label?: Uint8Array): Uint8Array;

export function startBaseOTPhase(participantId: number, others: Set<number>, pkBase: Uint8Array, numBaseOt?: number): [Uint8Array, Map<number, Uint8Array>];

export function baseOTPhaseProcessSenderPubkey(baseOTPhase: Uint8Array, senderId: number, publicKeyAndProof: Uint8Array, pkBase: Uint8Array): [Uint8Array, Uint8Array];

export function baseOTPhaseProcessReceiverPubkey(baseOTPhase: Uint8Array, receiverId: number, publicKey: Uint8Array, ): [Uint8Array, Uint8Array];

export function baseOTPhaseProcessChallenges(baseOTPhase: Uint8Array, senderId: number, challenges: Uint8Array): [Uint8Array, Uint8Array];

export function baseOTPhaseProcessResponses(baseOTPhase: Uint8Array, senderId: number, responses: Uint8Array): [Uint8Array, Uint8Array];

export function baseOTPhaseProcessHashedKeys(baseOTPhase: Uint8Array, senderId: number, hashedKeys: Uint8Array): Uint8Array;

export function baseOTPhaseFinish(baseOTPhase: Uint8Array): Uint8Array;

export function baseOTOutputCheck(baseOTOutputs: Uint8Array[]);

// Following are for BBS+

export function thresholdBbsPlusStartPhase1(sigBatchSize: number, participantId: number, others: Set<number>, protocolId: Uint8Array): [Uint8Array, Uint8Array, Map<number, Uint8Array>];

export function thresholdBbsPlusPhase1ProcessCommitments(phase1: Uint8Array, senderId: number, commitments: Uint8Array, commitmentsZeroShare: Uint8Array): Uint8Array;

export function thresholdBbsPlusPhase1GetSharesForOther(phase1: Uint8Array, otherId: number): [Uint8Array, Uint8Array];

export function thresholdBbsPlusPhase1GetSharesForOthers(phase1: Uint8Array, otherIds: number[]): [Uint8Array, Uint8Array][];

export function thresholdBbsPlusPhase1ProcessShares(phase1: Uint8Array, senderId: number, shares: Uint8Array, zeroShares: Uint8Array): Uint8Array;

export function thresholdBbsPlusPhase1Finish(phase1: Uint8Array, secretKey: Uint8Array): Uint8Array;

export function thresholdBbsPlusPhase2Start(participantId: number, others: Set<number>, phase1Output: Uint8Array, baseOTOutput: Uint8Array, gadgetVector: Uint8Array): [Uint8Array, Map<number, Uint8Array>];

export function thresholdBbsPlusPhase2ReceiveMessage1(phase2: Uint8Array, senderId: number, message: Uint8Array, gadgetVector: Uint8Array): [Uint8Array, Uint8Array];

export function thresholdBbsPlusPhase2ReceiveMessage2(phase2: Uint8Array, senderId: number, message: Uint8Array, gadgetVector: Uint8Array): Uint8Array;

export function thresholdBbsPlusPhase2Finish(phase2: Uint8Array): Uint8Array;

export function thresholdBbsPlusCreateSignatureShare(messages: Uint8Array[], indexInOutput: number, phase1Output: Uint8Array, phase2Output: Uint8Array, params: BbsPlusSigParams, encodeMessages: boolean): Uint8Array;

export function thresholdBbsPlusAggregateSignatureShares(shares: Uint8Array[]): Uint8Array;

// Following are for BBS

export function thresholdBbsStartPhase1(sigBatchSize: number, participantId: number, others: Set<number>, protocolId: Uint8Array): [Uint8Array, Uint8Array, Map<number, Uint8Array>];

export function thresholdBbsPhase1ProcessCommitments(phase1: Uint8Array, senderId: number, commitments: Uint8Array, commitmentsZeroShare: Uint8Array): Uint8Array;

export function thresholdBbsPhase1GetSharesForOther(phase1: Uint8Array, otherId: number): [Uint8Array, Uint8Array];

export function thresholdBbsPhase1GetSharesForOthers(phase1: Uint8Array, otherIds: number[]): [Uint8Array, Uint8Array][];

export function thresholdBbsPhase1ProcessShares(phase1: Uint8Array, senderId: number, shares: Uint8Array, zeroShares: Uint8Array): Uint8Array;

export function thresholdBbsPhase1Finish(phase1: Uint8Array, secretKey: Uint8Array): Uint8Array;

export function thresholdBbsPhase2Start(participantId: number, others: Set<number>, phase1Output: Uint8Array, baseOTOutput: Uint8Array, gadgetVector: Uint8Array): [Uint8Array, Map<number, Uint8Array>];

export function thresholdBbsPhase2ReceiveMessage1(phase2: Uint8Array, senderId: number, message: Uint8Array, gadgetVector: Uint8Array): [Uint8Array, Uint8Array];

export function thresholdBbsPhase2ReceiveMessage2(phase2: Uint8Array, senderId: number, message: Uint8Array, gadgetVector: Uint8Array): Uint8Array;

export function thresholdBbsPhase2Finish(phase2: Uint8Array): Uint8Array;

export function thresholdBbsCreateSignatureShare(messages: Uint8Array[], indexInOutput: number, phase1Output: Uint8Array, phase2Output: Uint8Array, params: BbsSigParams, encodeMessages: boolean): Uint8Array;

export function thresholdBbsAggregateSignatureShares(shares: Uint8Array[]): Uint8Array;