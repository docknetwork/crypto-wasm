export type CommitMessage =
  | {
      BlindMessageRandomly: Uint8Array;
    }
  | "RevealMessage"
  | {
      BlindMessageWithConcreteBlinding: {
        message: Uint8Array;
        blinding: Uint8Array;
      };
    };
