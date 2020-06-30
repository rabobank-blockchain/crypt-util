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
    if (this._hdnode) {
      return this._hdnode.derivePath(this.getPath(account, keyId)).privateKey
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Derives the corresponding public key for his specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived public key (prefixed with 0x)
   */
  public derivePublicKey (account: number, keyId: number): string {
    if (this._hdnode) {
      const compressedPublicKey = this._hdnode.derivePath(this.getPath(account, keyId)).publicKey
      return ethers.utils.computePublicKey(compressedPublicKey, false)
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Derives the corresponding address for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived address key, prefixed with 0x
   */
  public deriveAddress (account: number, keyId: number): string {
    if (this._hdnode) {
      return this._hdnode.derivePath(this.getPath(account, keyId)).address
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Computes an address out of an uncompressed public key
   * @param publicKey the full, uncompressed public key
   * @return string the new derived address key, prefixed with 0x
   */
  public getAddressFromPubKey (publicKey: string): string {
    return ethers.utils.computeAddress(publicKey)
  }

  /**
   * Derives the corresponding public extended key for his specific account(id) and key(id) using accountid and keyid
   * @param account the account ID
   * @param keyId the key ID
   * @return string the new derived public extended key
   */
  public derivePublicExtendedKey (account: number, keyId: number): string {
    if (this._hdnode) {
      return this._hdnode.derivePath(this.getPath(account, keyId)).neuter().extendedKey
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Derives the corresponding public extended key for his specific path
   * @param path the literal hdkey path
   * @return string the new derived public extended key
   */
  public derivePublicExtendedKeyFromPath (path: string): string {
    if (this._hdnode) {
      return this._hdnode.derivePath(path).neuter().extendedKey
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Derives the corresponding private extended key for his specific path
   * @param path the literal hdkey path
   * @return string the new derived private extended key
   */
  public derivePrivateKeyFromPath (path: string): string {
    if (this._hdnode) {
      return this._hdnode.derivePath(path).privateKey
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
  }

  /**
   * Signs a certain payload with the corresponding key for this specific account(id) and key(id)
   * @param account the account ID
   * @param keyId the key ID
   * @param payload the payload which will be signed
   * @return string the signature
   */
  public signPayload (account: number, keyId: number, message: string): string {
    if (this._hdnode) {
      const childPrivateKey = this._hdnode.derivePath(this.getPath(account, keyId)).privateKey
      const messageBytes = ethers.utils.toUtf8Bytes(message)
      const messageDigest = ethers.utils.keccak256(messageBytes)
      const signingKey = new ethers.utils.SigningKey(childPrivateKey)
      return ethers.utils.joinSignature(signingKey.signDigest(messageDigest))
    } else {
      throw (new Error('No MasterPrivateKey instantiated'))
    }
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
    try {
      const address: string = (addressOrPublicKey.length > 42) ? ethers.utils.computeAddress(addressOrPublicKey) : addressOrPublicKey
      return ethers.utils.recoverAddress(messageDigest, signature) === address
    } catch {
      return false
    }
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
}
