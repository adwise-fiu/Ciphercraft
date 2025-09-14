/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.paillier;

import edu.fiu.adwise.ciphercraft.misc.HomomorphicException;
import edu.fiu.adwise.ciphercraft.misc.KeyFunctions;
import edu.fiu.adwise.ciphercraft.misc.ObjectIdentifier;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;

import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PUBLIC_KEY_END;
import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PUBLIC_KEY_START;

/**
 * Represents the public key for the Paillier cryptosystem.
 * This class implements the Serializable, Paillier_Key, PublicKey, Runnable, and CipherConstants interfaces.
 * It provides methods for key generation and serialization for encryption operations.
 */
public final class PaillierPublicKey extends KeyFunctions implements Serializable, PaillierKey, PublicKey {
	@Serial
	private static final long serialVersionUID = -4009702553030484256L;

	/** The size of the key in bits. */
	public final int key_size;

	/** The value of n, which is the product of two large primes (p and q). */
	final BigInteger n;

	/** The modulus, which is n^2 */
	final BigInteger modulus;

	/** The generator g used in the Paillier cryptosystem. */
	final BigInteger g;

	/** Cached value representing the encryption of zero. */
	BigInteger ZERO = null;

	/**
	 * Constructs a Paillier public key with the specified parameters.
	 *
	 * @param key_size The size of the key in bits.
	 * @param n        The value of n (product of two primes p and q).
	 * @param modulus  The modulus (n^2).
	 * @param g        The generator g.
	 */
	public PaillierPublicKey(int key_size, BigInteger n, BigInteger modulus, BigInteger g) {
		this.key_size = key_size;
		this.n = n;
		this.modulus = modulus;
		this.g = g;
	}

    /**
     * Loads a Paillier public key from a PEM-encoded file.
     *
     * @param keyFile the path to the PEM file containing the public key
     * @return a {@link PaillierPublicKey} instance parsed from the file
     * @throws IOException if an error occurs while reading or parsing the file
     */
    public static PaillierPublicKey fromFile(String keyFile) throws IOException {
        byte[] encoded = KeyFunctions.readPemFile(keyFile, PUBLIC_KEY_START, PUBLIC_KEY_END);
        return fromEncoded(encoded);
    }

    /**
	 * Retrieves the encryption of zero using this public key.
	 *
	 * @return The encryption of zero as a {@link BigInteger}.
	 * @throws HomomorphicException If an error occurs during encryption.
	 */
	public BigInteger ZERO() throws HomomorphicException {
		if (ZERO == null) {
			this.ZERO = PaillierCipher.encrypt(0, this);
		}
		return this.ZERO;
	}

	/**
	 * Returns a string representation of the public key.
	 *
	 * @return A string representation of the public key.
	 */
	public String toString() {
		String answer = "";
		answer += "k1 = " + this.key_size + ", " + '\n';
		answer += "n = " + this.n + ", " + '\n';
		answer += "modulus = " + this.modulus + '\n';
		answer += "g = " + this.g + '\n';
		return answer;
	}

	/**
	 * Reads a public key from a file.
	 *
	 * @param der encoded bytes of the key
	 * @return The {@link PaillierPublicKey} object.
	 * @throws IOException            If an I/O error occurs.
	 */
    public static PaillierPublicKey fromEncoded(byte [] der) throws IOException {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
        ASN1Sequence seq = (ASN1Sequence) spki.parsePublicKey();
        int keySize = ((ASN1Integer) seq.getObjectAt(0)).getValue().intValue();
        BigInteger n = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        BigInteger modulus = ((ASN1Integer) seq.getObjectAt(2)).getValue();
        BigInteger g = ((ASN1Integer) seq.getObjectAt(3)).getValue();
        return new PaillierPublicKey(keySize, n, modulus, g);
    }

	/**
	 * Retrieves the value of n, which is part of the Paillier key.
	 *
	 * @return The value of n as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return this.n;
	}

	/**
	 * Retrieves the modulus used in the Paillier cryptosystem.
	 *
	 * @return The modulus as a {@link BigInteger}.
	 */
	public BigInteger getModulus() {
		return this.modulus;
	}

	/**
	 * Returns the algorithm name for this key.
	 *
	 * @return The algorithm name ("Paillier").
	 */
	public String getAlgorithm() {
		return "Paillier";
	}

	/**
	 * Returns the format of the key encoding.
	 *
	 * @return The format ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded key as a byte array, or null if not supported.
	 */
    @Override
    public byte[] getEncoded() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(key_size));
            v.add(new ASN1Integer(n));
            v.add(new ASN1Integer(modulus));
            v.add(new ASN1Integer(g));
            ASN1Sequence seq = new DERSequence(v);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(ObjectIdentifier.getAlgorithm(this));
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, seq);
            return spki.getEncoded("DER");
        } catch (Exception e) {
            return null;
        }
    }

	/**
	 * Compares this public key with another object for equality.
	 *
	 * @param o The object to compare with.
	 * @return True if the objects are equal, false otherwise.
	 */
	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		PaillierPublicKey that = (PaillierPublicKey) o;
		return this.toString().equals(that.toString());
	}
}