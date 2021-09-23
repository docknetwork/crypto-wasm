export interface BbsKeypair {
  /**
   * Raw secret/private key value for the key pair
   */
  readonly secretKey: Uint8Array;
  /**
   * Raw public key value for the key pair
   */
  readonly publicKey: Uint8Array;
}
