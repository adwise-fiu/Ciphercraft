/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.dgk;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import edu.fiu.adwise.ciphercraft.misc.KeyFunctions;
import edu.fiu.adwise.ciphercraft.misc.ObjectIdentifier;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import edu.fiu.adwise.ciphercraft.misc.CipherConstants;
import edu.fiu.adwise.ciphercraft.misc.HomomorphicException;

/**
 * Represents the public key for the DGK (Damgård-Geisler-Krøigaard) cryptosystem.
 * This class implements the Serializable, DGK_Key, PublicKey, Runnable, and CipherConstants interfaces.
 * It provides methods for key generation, serialization, and lookup table generation for encryption operations.
 */
public final class DGKPublicKey extends KeyFunctions implements Serializable, DGK_Key, PublicKey, Runnable, CipherConstants {
	@Serial
	private static final long serialVersionUID = -1613333167285302035L;

	/** The modulus \( n \) used in the DGK cryptosystem. */
	final BigInteger n;

	/** The generator \( g \) used in the DGK cryptosystem. */
	final BigInteger g;

	/** The secondary generator \( h \) used in the DGK cryptosystem. */
	final BigInteger h;

	/** The order of the subgroup as a long value. */
	final long u;

	/** The order of the subgroup as a BigInteger. */
	final BigInteger bigU;

	/** The lookup table for \( g^i \mod n \) values. */
	final Map<Long, BigInteger> gLUT = new HashMap<>();

	/** The lookup table for \( h^i \mod n \) values. */
	private final Map<Long, BigInteger> hLUT = new HashMap<>();

	// Key Parameters
	/** The bit length of plaintext values. */
	final int l;

	/** The security parameter used in the DGK cryptosystem. */
	final int t;

	/** The key length used in the DGK cryptosystem. */
	final int k;

	/** The encrypted representation of the value 1. */
	private BigInteger ONE = null;

	/** The encrypted representation of the value 0. */
	private BigInteger ZERO = null;

	/**
	 * Constructs a DGKPublicKey with all required parameters.
	 *
	 * @param n The modulus.
	 * @param g The generator.
	 * @param h The secondary generator.
	 * @param u The order of the subgroup.
	 * @param l The bit length of plaintext.
	 * @param t The security parameter.
	 * @param k The key size.
	 */
	public DGKPublicKey(BigInteger n, BigInteger g, BigInteger h, BigInteger u,
						int l, int t, int k) {
		this.n = n;
		this.g = g;
		this.h = h;
		this.u = u.longValue();
		this.bigU = u;
		this.l = l; 
		this.t = t;
		this.k = k;
	}

    public static DGKPublicKey fromFile(String keyFile) throws IOException {
        byte[] encoded = KeyFunctions.readPemFile(keyFile, PUBLIC_KEY_START, PUBLIC_KEY_END);
        return fromEncoded(encoded);
    }

    /**
     * Reconstructs a {@code DGKPublicKey} instance from DER-encoded bytes.
     * <p>
     * The encoded bytes should represent a DGK public key in X.509 SubjectPublicKeyInfo format,
     * containing the modulus, generators, subgroup order, and key parameters.
     * </p>
     *
     * @param encoded the DER-encoded byte array representing the DGK public key
     * @return a {@code DGKPublicKey} instance parsed from the encoded bytes
     * @throws IOException if the encoded bytes cannot be parsed or are invalid
     */
    public static DGKPublicKey fromEncoded(byte[] encoded) throws IOException {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encoded));
            ASN1Sequence seq = (ASN1Sequence) spki.parsePublicKey();
            BigInteger n = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger g = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            BigInteger h = ((ASN1Integer) seq.getObjectAt(2)).getValue();
            BigInteger bigU = ((ASN1Integer) seq.getObjectAt(3)).getValue();
            int l = ((ASN1Integer) seq.getObjectAt(4)).getValue().intValue();
            int t = ((ASN1Integer) seq.getObjectAt(5)).getValue().intValue();
            int k = ((ASN1Integer) seq.getObjectAt(6)).getValue().intValue();
            return new DGKPublicKey(n, g, h, bigU, l, t, k);
        } catch (Exception e) {
            throw new IOException("Failed to parse encoded DGKPublicKey", e);
        }
    }

	/**
	 * @return The encrypted representation of 0.
	 * @throws HomomorphicException - If an invalid input was found, this should be impossible in this case
	 */
	public BigInteger ZERO() throws HomomorphicException {
		if (ZERO == null) {
			ZERO = DGKOperations.encrypt(0, this);
		}
		return ZERO;
	}

	/**
	 * @return The encrypted representation of 1.
	 * @throws HomomorphicException - If an invalid input was found, this should be impossible in this case
	 */
	public BigInteger ONE() throws HomomorphicException {
		if (ONE == null) {
			ONE = DGKOperations.encrypt(1, this);
		}
		return ONE;
	}

	/**
	 * @return The algorithm name ("DGK").
	 */
	public String getAlgorithm() {
		return "DGK";
	}

	/**
	 * @return A string representation of the DGK public key.
	 */
	public String toString() {
		String answer = "";
		answer += "n: " + n + ", " + '\n';
		answer += "g: " + g + ", " + '\n';
		answer += "h: " + h + ", " + '\n';
		answer += "u: " + bigU + ", " + '\n';
		answer += "l: " + l + ", " + '\n';
		answer += "t: " + t + ", " + '\n';
		answer += "k: " + k + ", " + '\n';
		return answer;
	}

	/**
	 * @return The format of the key ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
     * @return The encoded form of the key (currently null).
     */
    @Override
    public byte[] getEncoded() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(n));
            v.add(new ASN1Integer(g));
            v.add(new ASN1Integer(h));
            v.add(new ASN1Integer(bigU));
            v.add(new ASN1Integer(l));
            v.add(new ASN1Integer(t));
            v.add(new ASN1Integer(k));
            ASN1Sequence seq = new DERSequence(v);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(ObjectIdentifier.getAlgorithm(this));
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, seq);
            return spki.getEncoded("DER");
        } catch (Exception e) {
            return null;
        }
    }

	/**
	 * Generates the lookup tables for g and h.
	 */
	public void run() {
		this.generatehLUT();
		this.generategLUT();
	}

	/**
	 * Generates the lookup table for h^i mod n values.
	 */
	private void generatehLUT() {		
		for (long i = 0; i < 2L * t; ++i) {
			// e = 2^i (mod n)
			// h^{2^i (mod n)} (mod n)
			// f(i) = h^{2^i}(mod n)
			BigInteger e = TWO.pow((int) i).mod(this.n);
			this.hLUT.put(i, this.h.modPow(e, this.n));
		}
	}

	/**
	 * Generates the lookup table for g^i mod n values.
	 */
	private void generategLUT() {	
		for (long i = 0; i < this.u; ++i) {
			BigInteger out = this.g.modPow(BigInteger.valueOf(i), this.n);
			this.gLUT.put(i, out);
		}
	}

	/**
	 * @return The order of the subgroup as a long.
	 */
	public long getu() {
		return this.u;
	}

	/**
	 * @return The order of the subgroup as a BigInteger.
	 */
	public BigInteger getU() {
		return this.bigU;
	}

	/**
	 * @return The modulus n.
	 */
	public BigInteger getN() {
		return this.n;
	}

	/**
	 * @return The bit length of plaintext.
	 */
	public int getL() {
		return this.l;
	}

	/**
	 * @return The security parameter.
	 */
	public int getT() {
		return this.t;
	}

	/**
	 * Compares this DGKPublicKey with another object for equality.
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
		DGKPublicKey that = (DGKPublicKey) o;
		return this.toString().equals(that.toString());
	}
}