/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.elgamal;

import edu.fiu.adwise.ciphercraft.misc.ObjectIdentifier;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/**
 * Represents the public key for the ElGamal encryption scheme.
 */
public final class ElGamalPublicKey implements Serializable, PublicKey, ElGamal_Key {
	@Serial
	private static final long serialVersionUID = -6796919675914392847L;
	/** The prime modulus \( p \) used in the ElGamal encryption scheme. */
	final BigInteger p;

	/** The generator \( g \) used in the ElGamal encryption scheme. */
	final BigInteger g;

	/** The public key component \( h \) derived from \( g^x \mod p \). */
	final BigInteger h;

	/** Indicates whether additive homomorphic encryption is enabled. */
	public boolean additive;

	/**
	 * Constructs an ElGamalPublicKey with the specified parameters.
	 *
	 * @param p The prime modulus.
	 * @param g The generator.
	 * @param h The public key component.
	 * @param additive Whether the key is used for additive homomorphism.
	 */
	public ElGamalPublicKey(BigInteger p, BigInteger g, BigInteger h, boolean additive) {
		this.p = p;
		this.g = g;
		this.h = h;
		this.additive = additive;
	}

	/**
	 * Sets whether the key is used for additive homomorphism.
	 *
	 * @param additive True if the key is additive, false otherwise.
	 */
	public void set_additive(boolean additive) {
		this.additive = additive;
	}

	/**
	 * Returns the algorithm name.
	 *
	 * @return The algorithm name ("ElGamal").
	 */
	public String getAlgorithm() {
		return "ElGamal";
	}

	/**
	 * Returns the format of the key.
	 *
	 * @return The format of the key ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded form of the key
	 */
    @Override
    public byte[] getEncoded() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(p));
            v.add(new ASN1Integer(g));
            v.add(new ASN1Integer(h));
            v.add(ASN1Boolean.getInstance(additive));
            ASN1Sequence seq = new DERSequence(v);

            // Use a custom OID for ElGamal or a placeholder
            AlgorithmIdentifier algId = new AlgorithmIdentifier(ObjectIdentifier.getAlgorithm(this));
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, seq);
            return spki.getEncoded("DER");
        } catch (Exception e) {
            return null;
        }
    }

	/**
	 * Returns the prime modulus.
	 *
	 * @return The prime modulus.
	 */
	public BigInteger getP() {
		return this.p;
	}

	/**
	 * Returns a string representation of the ElGamal public key.
	 *
	 * @return A string representation of the key.
	 */
	public String toString() {
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		return answer;
	}
}
