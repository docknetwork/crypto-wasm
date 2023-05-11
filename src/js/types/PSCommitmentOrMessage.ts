export type PSCommitmentOrMessage =
  | {
      BlindedMessage: Uint8Array;
    }
  | {
      RevealedMessage: Uint8Array;
    };
