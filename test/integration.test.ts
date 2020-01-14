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

import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import * as sinon from 'sinon'
import { LocalCryptUtils } from '../src'
import { ethers } from 'ethers'

const assert = chai.assert

before(() => {
  chai.should()
  chai.use(chaiAsPromised)
})

describe('cryptutils integration with libs', () => {
  // Test variables
  const account = 0
  const keyId = 3
  const derivedAccount = 314
  const derivedKeyId = 152679
  const privExtKey = 'xprv9s21ZrQH143K4Hahxy3chUqrrHbCynU5CcnRg9xijCvCG4f3AJb1PgiaXpjik6pDnT1qRmf3V3rzn26UNMWDjfEpUKL4ouy6t5ZVa4GAJVG'
  const signature = '0x7129ab6ac278c4d1ab120292ada929b1638eb654a11e6929c2490898bc2b4e6f15a9626d51f1aa2717356fc0d39ae8b9f83beeee061655e16de4f76d683da44d1b'
  const publicKey = '0x04dc07a3c64c076aab718c0392c7598a03eb669b7bd94a88a178846833c5b1d5724b9bf9082f1efbda048e0ca1bdfa075f7c10a35d89d4cf5a032fa7627a0a6f34'
  const address = '0x6Cb8b9B321cfefECB9a0e5B3EB0536962289711a'
  const payload = 'This is a test'
  let sut = new LocalCryptUtils()

  afterEach(() => {
    sinon.restore()
    sut = new LocalCryptUtils()
  })

  it('should import a private extended key', () => {
    // Act
    sut.importMasterPrivateKey(privExtKey)
    const exportPrivExtKey = sut.exportMasterPrivateKey()
    // Assert
    assert.equal(privExtKey, exportPrivExtKey)
  })

  it('should derive correct address', () => {
    // Act
    sut.importMasterPrivateKey(privExtKey)
    const address = sut.deriveAddress(0, 0)
    // Assert
    assert.equal(address, '0xa7756a3f0C60F353e7301F960b00C796C16065C9')
  })

  it('should deliver different keys when newly constructed', () => {
    // Arrange
    const sut1 = new LocalCryptUtils()
    const sut2 = new LocalCryptUtils()
    // Act
    sut1.createMasterPrivateKey()
    sut2.createMasterPrivateKey()
    const privExtKey1 = sut1.exportMasterPrivateKey()
    const privExtKey2 = sut2.exportMasterPrivateKey()
    // Assert
    assert.notEqual(privExtKey1, privExtKey2)
  })

  it('should successfully verify a valid signature', () => {
    // Arrange
    sut.createMasterPrivateKey()
    const pubKey = sut.derivePublicKey(account, keyId)
    // Act
    const signature = sut.signPayload(account, keyId, payload)
    const verified = sut.verifyPayload(payload, pubKey, signature)
    // Assert
    assert.isTrue(verified)
  })

  it('should not positively verify a wrong signature', () => {
    // Arrange
    sut.createMasterPrivateKey()
    // Act
    const signature = sut.signPayload(account, keyId, payload + 'wrong')
    const verified = sut.verifyPayload(payload, address, signature)
    // Assert
    assert.isNotTrue(verified)
  })

  it('should import a private extended key', () => {
    // Arrange
    const importPrivExtKey = privExtKey
    // Act
    sut.importMasterPrivateKey(importPrivExtKey)
    const exportPrivExtKey = sut.exportMasterPrivateKey()
    // Assert
    assert.equal(importPrivExtKey, exportPrivExtKey)
  })

  it('should derive the correct private key', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const privKey = sut.derivePrivateKey(derivedAccount, derivedKeyId)
    // Assert
    assert.strictEqual(privKey, '0xd9be5393869f3921ac0ede88e8c836f4d7c8a29def749c0fec35097d4355fc1b')
  })

  it('should derive the correct public key', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const pubKey = sut.derivePublicKey(derivedAccount, derivedKeyId)
    // Assert
    assert.strictEqual(pubKey, '0x04dc07a3c64c076aab718c0392c7598a03eb669b7bd94a88a178846833c5b1d5724b9bf9082f1efbda048e0ca1bdfa075f7c10a35d89d4cf5a032fa7627a0a6f34')
  })

  it('should derive the correct public extended key', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const pubKey = sut.derivePublicExtendedKey(derivedAccount, derivedKeyId)
    // Assert
    assert.strictEqual(pubKey, 'xpub6HGpFaxEhavCKxZCKu5M3qQs47E8WzT5xtRN6ALTBckgfQsJHM6ASC6nSPXRwbTU9kL8iJ6pztwTqWf6RFXmRqG1G5L57HkVQ4eC1WVUwR1')
  })

  it('should derive the correct public extended key', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const pubKey = sut.derivePublicExtendedKeyFromPath(`m/44'/60'/${derivedAccount}'/0'/${derivedKeyId}'`)
    // Assert
    assert.strictEqual(pubKey, 'xpub6HGpFaxEhavCKxZCKu5M3qQs47E8WzT5xtRN6ALTBckgfQsJHM6ASC6nSPXRwbTU9kL8iJ6pztwTqWf6RFXmRqG1G5L57HkVQ4eC1WVUwR1')
  })

  it('should derive the correct private key from path', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const privKey = sut.derivePrivateKeyFromPath(`m/44'/60'/${derivedAccount}'/0'/${derivedKeyId}'`)
    // Assert
    assert.strictEqual(privKey, '0xd9be5393869f3921ac0ede88e8c836f4d7c8a29def749c0fec35097d4355fc1b')
  })

  it('should create correct signature for certain payload', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    // Act
    const signature = sut.signPayload(derivedAccount, derivedKeyId, payload)
    // Assert
    assert.strictEqual(signature, '0x7129ab6ac278c4d1ab120292ada929b1638eb654a11e6929c2490898bc2b4e6f15a9626d51f1aa2717356fc0d39ae8b9f83beeee061655e16de4f76d683da44d1b')
  })

  it('should verify signature correct for certain payload', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    const signature = sut.signPayload(derivedAccount, derivedKeyId, payload)

    // Act
    const verified = sut.verifyPayload(payload, address, signature)
    // Assert
    assert.isTrue(verified)
  })

  it('should not verify signature correct for certain incorrect pubkey combi', () => {
    // Arrange
    sut.importMasterPrivateKey(privExtKey)
    const wrongPubKey = sut.derivePublicKey(3, 3)
    // Act
    const verified = sut.verifyPayload(payload, wrongPubKey, signature)
    // Assert
    assert.isNotTrue(verified)
  })

  it('should not verify signature correct for certain incorrect signature combi', () => {
    // Arrange
    const wrongSignature = '0xddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b81c'
    // Act
    const verified = sut.verifyPayload(payload, address, wrongSignature)
    // Assert
    assert.isNotTrue(verified)
  })

  it('should not verify signature correct for certain incorrect payload combi', () => {
    // Arrange
    const incorrectPayload = 'This is a wrong payload'
    // Act
    const verified = sut.verifyPayload(incorrectPayload, address, signature)
    // Assert
    assert.isNotTrue(verified)
  })

})
