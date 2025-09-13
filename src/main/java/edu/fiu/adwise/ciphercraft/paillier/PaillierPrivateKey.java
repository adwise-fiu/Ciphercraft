/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.paillier;

import edu.fiu.adwise.ciphercraft.misc.KeyFunctions;
import edu.fiu.adwise.ciphercraft.misc.ObjectIdentifier;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;

import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PRIVATE_KEY_END;
import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PRIVATE_KEY_START;


/**
 * This class represents a private key in the Paillier cryptosystem.
 * It implements the {@link PaillierKey} and {@link PrivateKey} interfaces
 * and is also serializable.
 */
public final class PaillierPrivateKey extends KeyFunctions implements Serializable, PaillierKey, PrivateKey {
	@Serial
	private static final long serialVersionUID = -3342551807566493368L;

	/** The security parameter \( k_1 \), representing the number of bits in \( n \). */
	private final int key_size;

	/** The value of \( n \), which is the product of two large primes \( p \) and \( q \). */
	final BigInteger n;

	/** The modulus \( n^2 \), used in the Paillier cryptosystem. */
	final BigInteger modulus;

	/** The generator \( g \), used in the encryption process. */
	final BigInteger g;

	/** The Carmichael's function value \( \lambda \), calculated as lcm(\( p-1 \), \( q-1 \)). */
	final BigInteger lambda;

	/** The modular inverse of \( \lambda \) modulo \( n \). */
	private final BigInteger mu;

	/** The precomputed value \( \rho \), used for decryption optimization. */
	final BigInteger rho;

	/** The smallest divisor of lcm(\( p-1 \), \( q-1 \)). */
	private final BigInteger alpha;

	/**
	 * Constructs a Paillier private key with the specified parameters.
	 *
	 * @param key_size The size of the key in bits.
	 * @param n        The value of n (product of two primes p and q).
	 * @param mod      The modulus (n^2).
	 * @param lambda   The Carmichael's function value.
	 * @param mu       The modular inverse of lambda mod n.
	 * @param g        The generator g.
	 * @param alpha    The smallest divisor of lcm(p-1, q-1).
	 */
	public PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
			BigInteger lambda, BigInteger mu, BigInteger g, BigInteger alpha) {
		this.key_size = key_size;
		this.n = n;
		this.modulus = mod;
		this.lambda = lambda;
		this.mu = mu;
		this.g = g;
		this.alpha = alpha;
		this.rho = PaillierCipher.L(this.g.modPow(this.lambda, this.modulus), this.n).modInverse(this.modulus);
	}

    public static PaillierPrivateKey fromFile(String keyFile) throws IOException {
        byte[] encoded = KeyFunctions.readPemFile(keyFile, PRIVATE_KEY_START, PRIVATE_KEY_END);
        return fromEncoded(encoded);
    }

	/**
	 * Reads a private key from a file.
	 *
	 * @param der the encoded bytes of the key
	 * @return The {@link PaillierPrivateKey} object.
	 * @throws IOException            If an I/O error occurs.
	 */
    public static PaillierPrivateKey fromEncoded(byte [] der) throws IOException {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
        ASN1Sequence seq = (ASN1Sequence) pkInfo.parsePrivateKey();
        int key_size = ((ASN1Integer) seq.getObjectAt(0)).getValue().intValue();
        BigInteger n = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        BigInteger modulus = ((ASN1Integer) seq.getObjectAt(2)).getValue();
        BigInteger lambda = ((ASN1Integer) seq.getObjectAt(3)).getValue();
        BigInteger mu = ((ASN1Integer) seq.getObjectAt(4)).getValue();
        BigInteger g = ((ASN1Integer) seq.getObjectAt(5)).getValue();
        BigInteger alpha = ((ASN1Integer) seq.getObjectAt(6)).getValue();
        // rho is optional for reconstruction but included for completeness
        BigInteger rho = ((ASN1Integer) seq.getObjectAt(7)).getValue();
        return new PaillierPrivateKey(key_size, n, modulus, lambda, mu, g, alpha);
    }

	/**
	 * Returns a string representation of the private key, omitting secret parameters.
	 *
	 * @return A string representation of the private key.
	 */
	public String toString() {
		String answer = "";
		answer += "key_size = " + this.key_size + ", " + '\n';
		answer += "n =        " + this.n + ", " + '\n';
		answer += "modulus =  " + this.modulus + '\n';
		answer += "g =        " + this.g + '\n';
		return answer;
	}

	/**
	 * Retrieves the value of n, which is part of the Paillier key.
	 *
	 * @return The value of n as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return n;
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
	 * @return The format ("PKCS#8").
	 */
	public String getFormat() {
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded key as a byte array, or null if not supported.
	 */
    public byte[] getEncoded() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(key_size));
            v.add(new ASN1Integer(n));
            v.add(new ASN1Integer(modulus));
            v.add(new ASN1Integer(lambda));
            v.add(new ASN1Integer(mu));
            v.add(new ASN1Integer(g));
            v.add(new ASN1Integer(alpha));
            v.add(new ASN1Integer(rho));
            ASN1Sequence seq = new DERSequence(v);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(ObjectIdentifier.getAlgorithm(this));
            PrivateKeyInfo pkInfo = new PrivateKeyInfo(algId, seq);
            return pkInfo.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

	/**
	 * Compares this private key with another object for equality.
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
		PaillierPrivateKey that = (PaillierPrivateKey) o;
		return this.toString().equals(that.toString());
	}
}