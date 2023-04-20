export type CommitmentOrMessage =
  | {
      BlindedMessage: Uint8Array;
    }
  | {
      RevealedMessage: Uint8Array;
    };
