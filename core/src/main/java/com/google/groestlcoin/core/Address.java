/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.groestlcoin.core;

import com.google.groestlcoin.params.MainNetParams;
import com.google.groestlcoin.params.TestNet3Params;
import com.google.groestlcoin.script.Script;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>A Bitcoin address looks like 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy and is derived from an elliptic curve public key
 * plus a set of network parameters. Not to be confused with a {@link PeerAddress} or {@link AddressMessage}
 * which are about network (TCP) addresses.</p>
 *
 * <p>A standard address is built by taking the RIPE-MD160 hash of the public key bytes, with a version prefix and a
 * checksum suffix, then encoding it textually as base58. The version prefix is used to both denote the network for
 * which the address is valid (see {@link NetworkParameters}, and also to indicate how the bytes inside the address
 * should be interpreted. Whilst almost all addresses today are hashes of public keys, another (currently unsupported
 * type) can contain a hash of a script instead.</p>
 */
public class Address extends VersionedChecksummedBytes {
    /**
     * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
     */
    public static final int LENGTH = 20;
    /**
     * Construct an address from parameters, the address version, and the hash160 form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), NetworkParameters.getAddressHeader(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    public Address(NetworkParameters params, int version, byte[] hash160) {
        super(version, hash160);
        if (!isAcceptableVersion(params, version))
            throw new RuntimeException("Unrecognized Address version");
        if (hash160.length != 20)  // 160 = 8 * 20
            throw new RuntimeException("Addresses are 160-bit hashes, so you must provide 20 bytes");
    }

    /**
     * Construct an address from parameters and the hash160 form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    public Address(NetworkParameters params, byte[] hash160) {
        this(params, params.getAddressHeader(), hash160);
    }

    /**
     * Construct an address from parameters and the standard "human readable" form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");</pre><p>
     *
     * @param params The expected NetworkParameters or null if you don't want validation.
     * @param address The textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL"
     * @throws AddressFormatException if the given address doesn't parse or the checksum is invalid
     * @throws WrongNetworkException if the given address is valid but for a different chain (eg testnet vs prodnet)
     */
    public Address(@Nullable NetworkParameters params, String address) throws AddressFormatException, WrongNetworkException {
        super(address);
        if (params != null) {
            if (!isAcceptableVersion(params, version)) {
                throw new WrongNetworkException(version, params.getAcceptableAddressCodes());
            }
        }
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    public byte[] getHash160() {
        return bytes;
    }

    /**
     * Returns true if this address is a Pay-To-Script-Hash (P2SH) address.
     * See also https://en.bitcoin.it/wiki/BIP_0013: Address Format for pay-to-script-hash
     */
    public boolean isP2SHAddress() {
        return this.version == getParameters().p2shHeader;
    }

    /** Returns an Address that represents the given P2SH script hash. */
    public static Address fromP2SHHash(NetworkParameters params, byte[] hash160) {
        return new Address(params, params.getP2SHHeader(), hash160);
    }

    /** Returns an Address that represents the script hash extracted from the given scriptPubKey */
    public static Address fromP2SHScript(NetworkParameters params, Script scriptPubKey) throws ScriptException {
        checkArgument(scriptPubKey.isPayToScriptHash(), "Not a P2SH script");
        return fromP2SHHash(params, scriptPubKey.getPubKeyHash());
    }

    /**
     * Examines the version byte of the address and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method. Note that the
     * parameters returned is not necessarily the same as the one the Address was created with.
     *
     * @return a NetworkParameters representing the network the address is intended for, or null if unknown.
     */
    public NetworkParameters getParameters() {
        // TODO: There should be a more generic way to get all supported networks.
        NetworkParameters[] networks = { MainNetParams.get() };
        for (NetworkParameters params : networks) {
            if (isAcceptableVersion(params, version)) {
                return params;
            }
        }
        return null;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method.
     */
    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
        try {
            return new Address(null, address).getParameters();
        } catch (WrongNetworkException e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
    }

    /**
     * Check if a given address version is valid given the NetworkParameters.
     */
    private boolean isAcceptableVersion(NetworkParameters params, int version) {
        for (int v : params.getAcceptableAddressCodes()) {
            if (version == v) {
                return true;
            }
        }
        return false;
    }
}
