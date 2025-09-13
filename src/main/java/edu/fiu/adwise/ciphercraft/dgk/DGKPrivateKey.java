/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.dgk;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import edu.fiu.adwise.ciphercraft.misc.KeyFunctions;
import edu.fiu.adwise.ciphercraft.misc.NTL;
import edu.fiu.adwise.ciphercraft.misc.ObjectIdentifier;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PRIVATE_KEY_END;
import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PRIVATE_KEY_START;

/**
 * Represents a DGK (Damgård-Geisler-Krøigaard) private key used for homomorphic encryption.
 * This class implements the {@link Serializable}, {@link DGK_Key}, and {@link PrivateKey} interfaces.
 * It contains both private and public key parameters, as well as methods for key serialization,
 * deserialization, and lookup table generation.
 */
public final class DGKPrivateKey  extends KeyFunctions implements Serializable, DGK_Key, PrivateKey {
	@Serial
	private static final long serialVersionUID = 4574519230502483629L;

	// Private Key Parameters
	/** The first prime factor of the modulus \( n \). */
	final BigInteger p;

	/** The second prime factor of the modulus \( n \). */
	private final BigInteger q;

	/** A precomputed value for decryption using the first prime factor \( p \). */
	final BigInteger vp;

	/** A precomputed value for decryption using the second prime factor \( q \). */
	private final BigInteger vq;

	/** The lookup table (LUT) for decryption, mapping ciphertext values to plaintext values. */
	final Map<BigInteger, Long> LUT;

	// Public Key Parameters
	/** The modulus \( n \) used in the encryption scheme. */
	final BigInteger n;

	/** The generator \( g \) used in the encryption scheme. */
	final BigInteger g;

	/** An auxiliary generator \( h \) used in the encryption scheme. */
	private final BigInteger h;

	/** The upper bound for plaintext values in the encryption scheme. */
	private final long u;

	/** The BigInteger representation of the upper bound \( u \). */
	private final BigInteger bigU;

	// Key Parameters
	/** The bit length of plaintext values. */
	private final int l;

	/** The security parameter \( t \) used in the encryption scheme. */
	private final int t;

	/** The key length \( k \) used in the encryption scheme. */
	private final int k;

	// Signature
	/** The product of \( vp \) and \( vq \), used for decryption. */
	public final BigInteger v;

	/**
	 * Constructs a DGKPrivateKey using the provided private key parameters and public key.
	 *
	 * @param p       First prime factor of n
	 * @param q       Second prime factor of n
	 * @param vp      Precomputed value for decryption
	 * @param vq      Precomputed value for decryption
	 * @param pubKey  Corresponding DGK public key
	 */
	public DGKPrivateKey (BigInteger p, BigInteger q, BigInteger vp,
			BigInteger vq, DGKPublicKey pubKey) {
		this.p = p;
		this.q = q;
		this.vp = vp;
		this.vq = vq;
		this.v = vp.multiply(vq);

		// Public Key Parameters
		this.n = pubKey.n;
		this.g = pubKey.g;
		this.h = pubKey.h;
		this.u = pubKey.u;
		this.bigU = pubKey.bigU;

		// Key Parameters
		this.l = pubKey.l;
		this.t = pubKey.t;
		this.k = pubKey.k;

		// I already know the size of my map, so just initialize the size now to avoid memory waste!
		this.LUT = new HashMap<>((int) this.u, (float) 1.0);

		// Now that I have public key parameters, build LUT!
		this.generategLUT();
	}

    public static DGKPrivateKey fromFile(String keyFile) throws IOException {
        byte[] encoded = KeyFunctions.readPemFile(keyFile, PRIVATE_KEY_START, PRIVATE_KEY_END);
        return fromEncoded(encoded);
    }

    /**
     * Reads and parses a DGK private key from a PEM file in PKCS#8 ASN.1 format.
     *
     * @param encoded the bytes read from the file
     * @return The deserialized DGKPrivateKey object
     * @throws IOException            If an I/O error occurs during deserialization
     */
    public static DGKPrivateKey fromEncoded(byte [] encoded) throws IOException {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encoded));
        ASN1Sequence seq = (ASN1Sequence) pkInfo.parsePrivateKey();

        BigInteger p = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger q = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        BigInteger vp = ((ASN1Integer) seq.getObjectAt(2)).getValue();
        BigInteger vq = ((ASN1Integer) seq.getObjectAt(3)).getValue();
        BigInteger n = ((ASN1Integer) seq.getObjectAt(4)).getValue();
        BigInteger g = ((ASN1Integer) seq.getObjectAt(5)).getValue();
        BigInteger h = ((ASN1Integer) seq.getObjectAt(6)).getValue();
        long u = ((ASN1Integer) seq.getObjectAt(7)).getValue().longValue();
        int l = ((ASN1Integer) seq.getObjectAt(8)).getValue().intValue();
        int t = ((ASN1Integer) seq.getObjectAt(9)).getValue().intValue();
        int k = ((ASN1Integer) seq.getObjectAt(10)).getValue().intValue();

        DGKPublicKey pubKey = new DGKPublicKey(n, g, h, BigInteger.valueOf(u), l, t, k);
        DGKPrivateKey sk = new DGKPrivateKey(p, q, vp, vq, pubKey);
        sk.generategLUT();
        return sk;
    }

	/**
	 * Generates the lookup table (LUT) for decryption.
	 * The LUT maps ciphertext values to their corresponding plaintext values.
	 */
	private void generategLUT() {
		BigInteger gvp = NTL.POSMOD(this.g.modPow(this.vp, this.p), this.p);
		for (long i = 0; i < this.u; ++i)
		{
			BigInteger decipher = gvp.modPow(BigInteger.valueOf(i), this.p);
			this.LUT.put(decipher, i);
		}
	}

	/**
	 * Returns a string representation of the public key parameters.
	 * Private key parameters are excluded for security reasons.
	 *
	 * @return A string representation of the public key parameters
	 */
	public String toString() {
		String answer = "";
		answer += "n: " + this.n + '\n';
		answer += "g: " + this.g + '\n';
		answer += "h: " + this.h + '\n';
		answer += "u: " + this.bigU + '\n';
		answer += "l: " + this.l + '\n';
		answer += "t: " + this.t + '\n';
		answer += "k: " + this.k + '\n';
		// COMMENTED OUT TO HIDE SECRET KEY PARAMETERS
		return answer;
	}

	/**
	 * Returns the upper bound for plaintext values.
	 *
	 * @return The upper bound for plaintext values
	 */
	public BigInteger getU() {
		return this.bigU;
	}

	/**
	 * Returns the modulus of the key.
	 *
	 * @return The modulus of the key
	 */
	public BigInteger getN() {
		return this.n;
	}

	/**
	 * Returns the bit length of plaintext values.
	 *
	 * @return The bit length of plaintext values
	 */
	public int getL() {
		return this.l;
	}

	/**
	 * Returns the algorithm name.
	 *
	 * @return The algorithm name ("DGK")
	 */
	public String getAlgorithm() {
		return "DGK";
	}

	/**
	 * Returns the format of the key.
	 *
	 * @return The format of the key ("PKCS#8")
	 */
	public String getFormat() {
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the key.
	 * This implementation returns null as encoding is not supported.
	 *
	 * @return null
	 */
    public byte[] getEncoded() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(p));
            v.add(new ASN1Integer(q));
            v.add(new ASN1Integer(vp));
            v.add(new ASN1Integer(vq));
            v.add(new ASN1Integer(n));
            v.add(new ASN1Integer(g));
            v.add(new ASN1Integer(h));
            v.add(new ASN1Integer(u));
            v.add(new ASN1Integer(l));
            v.add(new ASN1Integer(t));
            v.add(new ASN1Integer(k));

            ASN1Sequence seq = new DERSequence(v);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(ObjectIdentifier.getAlgorithm(this));
            PrivateKeyInfo pkInfo = new PrivateKeyInfo(algId, seq);
            return pkInfo.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }


	/**
	 * Compares this DGKPrivateKey with another object for equality.
	 *
	 * @param o The object to compare with
	 * @return true if the objects are equal, false otherwise
	 */
	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DGKPrivateKey that = (DGKPrivateKey) o;
		return this.toString().equals(that.toString());
	}
}