/*
 * Copyright 2020 Coöperatieve Rabobank U.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// @ts-ignore
import { CryptUtil } from './interface/crypt-util'
import { ethers } from 'ethers'

const HDNode = ethers.utils.HDNode

enum HdNodeItem {
  PrivateKey,
  PrivateExtendedKey,
  PublicKey,
  PublicExtendedKey,
  Address
}

export class LocalCryptUtils implements CryptUtil {
  private _hdnode: ethers.utils.HDNode | undefined

  /**
   * Shows what kind of cryptographic algorithm is
   * using this instance.
   * @return string
   */
  get algorithmName (): string {
    return 'secp256k1'
  }

  /**
   * Creates the master private key, which can be exported for local storage
   */
  public createMasterPrivateKey (): void {
    this._hdnode = HDNode.fromSeed(ethers.utils.randomBytes(32))
    if (!this._hdnode) {
      throw new Error('Could not create master private key')
    }
  }

  /**
   * Exports the master private key
   * @return string the private key
   */
  public exportMasterPrivateKey (): string {
    if (this._hdnode) {
      return this._hdnode.extendedKey
    } else {
      throw(new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Imports a master private extended key
   * @param privExtKey the key to be imported
   */
  public importMasterPrivateKey (privExtKey: string): void {
    this._hdnode = HDNode.fromExtendedKey(privExtKey)
  }

  /**
   * Derives the corresponding private key for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived private key
   */
  public derivePrivateKey (account: number, keyId: number): string {
    return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PrivateKey)
  }

  /**
   * Derives the corresponding public key for his specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived public key (prefixed with 0x)
   */
  public derivePublicKey (account: number, keyId: number): string {
    return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PublicKey)
  }

  /**
   * Derives the corresponding address for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived address key, prefixed with 0x
   */
  public deriveAddress (account: number, keyId: number): string {
    return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.Address)
  }

  /**
   * Computes an address out of an uncompressed public key
   * @param publicKey the full, uncompressed public key
   * @return string the new derived address key, prefixed with 0x
   */
  public getAddressFromPubKey (publicKey: string): string {
    let correctFormatPubKey = publicKey
    if (publicKey.slice(0,4) !== '0x04') {
      if (publicKey.slice(0,2) === '04') {
        // assume only 0x forgotten
        correctFormatPubKey = '0x' + publicKey
      } else {
        correctFormatPubKey = '0x04' + publicKey
      }
    }
    return ethers.utils.computeAddress(correctFormatPubKey)
  }

  /**
   * Derives the corresponding public extended key for his specific account(id) and key(id) using accountid and keyid
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived public extended key
   */
  public derivePublicExtendedKey (account: number, keyId: number): string {
    return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PublicExtendedKey)
  }

  /**
   * Derives the corresponding public extended key for his specific path
   * @param path the literal hdkey path
   * @return string the new derived public extended key
   */
  public derivePublicExtendedKeyFromPath (path: string): string {
    return this.deriveHdNodeItemWithPath(path, HdNodeItem.PublicExtendedKey)
  }

  /**
   * Derives the corresponding private extended key for his specific path
   * @param path the literal hdkey path
   * @return string the new derived private extended key
   */
  public derivePrivateKeyFromPath (path: string): string {
    return this.deriveHdNodeItemWithPath(path, HdNodeItem.PrivateKey)
  }

  /**
   * Signs a certain payload with the corresponding key for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @param payload the payload which will be signed
   * @return string the signature
   */
  public signPayload (account: number, keyId: number, message: string): string {
    const childPrivateKey = this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PrivateKey)
    const messageBytes = ethers.utils.toUtf8Bytes(message)
    const messageDigest = ethers.utils.keccak256(messageBytes)
    const signingKey = new ethers.utils.SigningKey(childPrivateKey)
    return ethers.utils.joinSignature(signingKey.signDigest(messageDigest))
  }

  /**
   * Verifies that the signature over a payload is set by the owner of the publicKey
   * @param payload the payload which will be signed
   * @param address the address from the signer
   * @param signature the signature from the signer
   * @return boolean whether the payload is valid or not
   */
  public verifyPayload (message: string, addressOrPublicKey: string, signature: string): boolean {
    const messageBytes = ethers.utils.toUtf8Bytes(message)
    const messageDigest = ethers.utils.keccak256(messageBytes)
    let res = false
    try {
      const address: string = (addressOrPublicKey.length > 42) ? ethers.utils.computeAddress(addressOrPublicKey) : addressOrPublicKey
      res = ethers.utils.recoverAddress(messageDigest, signature) === address
    } catch {
      // Leave result false when error
    }

    return res
  }

  /**
   * Determine the correct getPath for Ethereum like key
   * for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new path
   */
  private getPath (account: number, keyId: number): string {
    return `m/44'/60'/${account}'/0'/${keyId}'`
  }

  private deriveHdNodeItemWithAccountAndKeyId (account: number, keyId: number, item: HdNodeItem): string {
    return this.deriveHdNodeItemWithPath(this.getPath(account, keyId), item)
  }

  private deriveHdNodeItemWithPath (path: string, item: HdNodeItem): string {
    let ret = ''
    if (this._hdnode) {
      const derivedNode = this._hdnode.derivePath(path)
      switch (item) {
        case HdNodeItem.PrivateKey:
          ret = derivedNode.privateKey
          break
        case HdNodeItem.PublicKey:
          const compressedPublicKey = derivedNode.publicKey
          ret = ethers.utils.computePublicKey(compressedPublicKey, false)
          break
        case HdNodeItem.PublicExtendedKey:
          ret = derivedNode.neuter().extendedKey
          break
        case HdNodeItem.Address:
          ret = derivedNode.address
      }
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
    return ret
  }

}
