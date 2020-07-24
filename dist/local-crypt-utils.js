"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalCryptUtils = void 0;
const ethers_1 = require("ethers");
const HDNode = ethers_1.ethers.utils.HDNode;
class LocalCryptUtils {
    /**
     * Shows what kind of cryptographic algorithm is
     * using this instance.
     * @return string
     */
    get algorithmName() {
        return 'secp256k1';
    }
    /**
     * Creates the master private key, which can be exported for local storage
     */
    createMasterPrivateKey() {
        this._hdnode = HDNode.fromSeed(ethers_1.ethers.utils.randomBytes(32));
        if (!this._hdnode) {
            throw new Error('Could not create master private key');
        }
    }
    /**
     * Exports the master private key
     * @return string the private key
     */
    exportMasterPrivateKey() {
        if (this._hdnode) {
            return this._hdnode.extendedKey;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Imports a master private extended key
     * @param privExtKey the key to be imported
     */
    importMasterPrivateKey(privExtKey) {
        this._hdnode = HDNode.fromExtendedKey(privExtKey);
    }
    /**
     * Derives the corresponding private key for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived private key
     */
    derivePrivateKey(account, keyId) {
        if (this._hdnode) {
            return this._hdnode.derivePath(this.getPath(account, keyId)).privateKey;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Derives the corresponding public key for his specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived public key (prefixed with 0x)
     */
    derivePublicKey(account, keyId) {
        if (this._hdnode) {
            const compressedPublicKey = this._hdnode.derivePath(this.getPath(account, keyId)).publicKey;
            return ethers_1.ethers.utils.computePublicKey(compressedPublicKey, false);
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Derives the corresponding address for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived address key, prefixed with 0x
     */
    deriveAddress(account, keyId) {
        if (this._hdnode) {
            return this._hdnode.derivePath(this.getPath(account, keyId)).address;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Computes an address out of an uncompressed public key
     * @param publicKey the full, uncompressed public key
     * @return string the new derived address key, prefixed with 0x
     */
    getAddressFromPubKey(publicKey) {
        return ethers_1.ethers.utils.computeAddress(publicKey);
    }
    /**
     * Derives the corresponding public extended key for his specific account(id) and key(id) using accountid and keyid
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived public extended key
     */
    derivePublicExtendedKey(account, keyId) {
        if (this._hdnode) {
            return this._hdnode.derivePath(this.getPath(account, keyId)).neuter().extendedKey;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Derives the corresponding public extended key for his specific path
     * @param path the literal hdkey path
     * @return string the new derived public extended key
     */
    derivePublicExtendedKeyFromPath(path) {
        if (this._hdnode) {
            return this._hdnode.derivePath(path).neuter().extendedKey;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Derives the corresponding private extended key for his specific path
     * @param path the literal hdkey path
     * @return string the new derived private extended key
     */
    derivePrivateKeyFromPath(path) {
        if (this._hdnode) {
            return this._hdnode.derivePath(path).privateKey;
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Signs a certain payload with the corresponding key for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @param payload the payload which will be signed
     * @return string the signature
     */
    signPayload(account, keyId, message) {
        if (this._hdnode) {
            const childPrivateKey = this._hdnode.derivePath(this.getPath(account, keyId)).privateKey;
            const messageBytes = ethers_1.ethers.utils.toUtf8Bytes(message);
            const messageDigest = ethers_1.ethers.utils.keccak256(messageBytes);
            const signingKey = new ethers_1.ethers.utils.SigningKey(childPrivateKey);
            return ethers_1.ethers.utils.joinSignature(signingKey.signDigest(messageDigest));
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
    }
    /**
     * Verifies that the signature over a payload is set by the owner of the publicKey
     * @param payload the payload which will be signed
     * @param address the address from the signer
     * @param signature the signature from the signer
     * @return boolean whether the payload is valid or not
     */
    verifyPayload(message, addressOrPublicKey, signature) {
        const messageBytes = ethers_1.ethers.utils.toUtf8Bytes(message);
        const messageDigest = ethers_1.ethers.utils.keccak256(messageBytes);
        try {
            const address = (addressOrPublicKey.length > 42) ? ethers_1.ethers.utils.computeAddress(addressOrPublicKey) : addressOrPublicKey;
            return ethers_1.ethers.utils.recoverAddress(messageDigest, signature) === address;
        }
        catch (_a) {
            return false;
        }
    }
    /**
     * Determine the correct getPath for Ethereum like key
     * for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new path
     */
    getPath(account, keyId) {
        return `m/44'/60'/${account}'/0'/${keyId}'`;
    }
}
exports.LocalCryptUtils = LocalCryptUtils;
//# sourceMappingURL=local-crypt-utils.js.map