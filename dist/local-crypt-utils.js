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
var HdNodeItem;
(function (HdNodeItem) {
    HdNodeItem[HdNodeItem["PrivateKey"] = 0] = "PrivateKey";
    HdNodeItem[HdNodeItem["PrivateExtendedKey"] = 1] = "PrivateExtendedKey";
    HdNodeItem[HdNodeItem["PublicKey"] = 2] = "PublicKey";
    HdNodeItem[HdNodeItem["PublicExtendedKey"] = 3] = "PublicExtendedKey";
    HdNodeItem[HdNodeItem["Address"] = 4] = "Address";
})(HdNodeItem || (HdNodeItem = {}));
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
        return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PrivateKey);
    }
    /**
     * Derives the corresponding public key for his specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived public key (prefixed with 0x)
     */
    derivePublicKey(account, keyId) {
        return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PublicKey);
    }
    /**
     * Derives the corresponding address for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @return string the new derived address key, prefixed with 0x
     */
    deriveAddress(account, keyId) {
        return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.Address);
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
        return this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PublicExtendedKey);
    }
    /**
     * Derives the corresponding public extended key for his specific path
     * @param path the literal hdkey path
     * @return string the new derived public extended key
     */
    derivePublicExtendedKeyFromPath(path) {
        return this.deriveHdNodeItemWithPath(path, HdNodeItem.PublicExtendedKey);
    }
    /**
     * Derives the corresponding private extended key for his specific path
     * @param path the literal hdkey path
     * @return string the new derived private extended key
     */
    derivePrivateKeyFromPath(path) {
        return this.deriveHdNodeItemWithPath(path, HdNodeItem.PrivateKey);
    }
    /**
     * Signs a certain payload with the corresponding key for this specific account(id) and key(id)
     * @param account the account ID
     * @param keyId the key ID
     * @param payload the payload which will be signed
     * @return string the signature
     */
    signPayload(account, keyId, message) {
        const childPrivateKey = this.deriveHdNodeItemWithAccountAndKeyId(account, keyId, HdNodeItem.PrivateKey);
        const messageBytes = ethers_1.ethers.utils.toUtf8Bytes(message);
        const messageDigest = ethers_1.ethers.utils.keccak256(messageBytes);
        const signingKey = new ethers_1.ethers.utils.SigningKey(childPrivateKey);
        return ethers_1.ethers.utils.joinSignature(signingKey.signDigest(messageDigest));
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
        let res = false;
        try {
            const address = (addressOrPublicKey.length > 42) ? ethers_1.ethers.utils.computeAddress(addressOrPublicKey) : addressOrPublicKey;
            res = ethers_1.ethers.utils.recoverAddress(messageDigest, signature) === address;
        }
        catch (_a) {
            // Leave result false when error
        }
        return res;
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
    deriveHdNodeItemWithAccountAndKeyId(account, keyId, item) {
        return this.deriveHdNodeItemWithPath(this.getPath(account, keyId), item);
    }
    deriveHdNodeItemWithPath(path, item) {
        let ret = '';
        if (this._hdnode) {
            const derivedNode = this._hdnode.derivePath(path);
            switch (item) {
                case HdNodeItem.PrivateKey:
                    ret = derivedNode.privateKey;
                    break;
                case HdNodeItem.PublicKey:
                    const compressedPublicKey = derivedNode.publicKey;
                    ret = ethers_1.ethers.utils.computePublicKey(compressedPublicKey, false);
                    break;
                case HdNodeItem.PublicExtendedKey:
                    ret = derivedNode.neuter().extendedKey;
                    break;
                case HdNodeItem.Address:
                    ret = derivedNode.address;
            }
        }
        else {
            throw (new Error('No MasterPrivateKey instantiated'));
        }
        return ret;
    }
}
exports.LocalCryptUtils = LocalCryptUtils;
//# sourceMappingURL=local-crypt-utils.js.map