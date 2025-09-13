/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.encryption_test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;

import edu.fiu.adwise.ciphercraft.socialistmillionaire.alice_joye;
import edu.fiu.adwise.ciphercraft.dgk.DGKOperations;
import edu.fiu.adwise.ciphercraft.dgk.DGKPrivateKey;
import edu.fiu.adwise.ciphercraft.dgk.DGKPublicKey;
import edu.fiu.adwise.ciphercraft.misc.HomomorphicException;
import edu.fiu.adwise.ciphercraft.misc.NTL;
import edu.fiu.adwise.ciphercraft.paillier.PaillierCipher;
import edu.fiu.adwise.ciphercraft.paillier.PaillierPrivateKey;
import edu.fiu.adwise.ciphercraft.paillier.PaillierPublicKey;
import edu.fiu.adwise.ciphercraft.socialistmillionaire.alice;

import static org.junit.Assert.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class test_alice implements Runnable, constants
{
	private static final Logger logger = LogManager.getLogger(test_alice.class);
	private final String alice_class;
	public test_alice(alice Niu, KeyPair paillier, KeyPair dgk) {
		this.Niu = Niu;
		if (paillier.getPrivate() instanceof PaillierPrivateKey) {
			this.paillier_private = (PaillierPrivateKey) paillier.getPrivate();
		}
		if (dgk.getPrivate() instanceof DGKPrivateKey) {
			this.dgk_private = (DGKPrivateKey) dgk.getPrivate();
		}
		alice_class = Niu.getClass().getName();
	}

	private final alice Niu;
	private static PaillierPublicKey paillier_public;
	private static DGKPublicKey dgk_public_key;

	private PaillierPrivateKey paillier_private;
	private DGKPrivateKey dgk_private;
	
	// Get your test data...
	private static final BigInteger [] low = IntegrationTests.generate_low();
	private static final BigInteger [] mid = IntegrationTests.generate_mid();
	private static final BigInteger [] high = IntegrationTests.generate_high();
	
	// This would have been in Alice's (Client) Main Function
	public void run() {
		try {
			paillier_public = Niu.getPaillierPublicKey();
			dgk_public_key = Niu.getDGKPublicKey();

			test_outsourced_multiply(true);
			test_outsourced_multiply(false);

			test_outsourced_division(true);
			test_outsourced_division(false);

			test_protocol_one(true);
			test_protocol_one(false);

			test_protocol_two(true);
			test_protocol_two(false);

			test_sorting(true);
			test_sorting(false);

			test_private_equality(true);
			test_private_equality(false);

			test_encrypted_equality(true);
			test_encrypted_equality(false);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public void test_sorting(boolean dgk_mode)
			throws ClassNotFoundException, IOException, HomomorphicException {

        logger.info("{}: Testing Sorting with DGK Mode: {}", alice_class, dgk_mode);
		BigInteger [] toSort = new BigInteger[low.length];
		BigInteger [] min;

		Niu.setDGKMode(dgk_mode);
		for(int i = 0; i < low.length; i++) {
			toSort[i] = NTL.generateXBitRandom(9);
			if (dgk_mode) {
				toSort[i] = DGKOperations.encrypt(toSort[i], dgk_public_key);
			}
			else {
				toSort[i] = PaillierCipher.encrypt(toSort[i], paillier_public);
			}
		}

		if (dgk_mode) {
			if (Niu.getClass() == alice.class) {
                logger.info("{}: Skipping Sorting because will crash with this alice version...", alice_class);
				return;
			}
		}

		min = Niu.getKValues(toSort, 3, true);
		for (int i = 0; i < min.length; i++) {
			if (dgk_mode) {
				min[i] = BigInteger.valueOf(DGKOperations.decrypt(min[i], dgk_private));
			}
			else {
				min[i] = PaillierCipher.decrypt(min[i], paillier_private);
			}
		}
		for (int i = 0; i < toSort.length; i++) {
			if (dgk_mode) {
				toSort[i] = BigInteger.valueOf(DGKOperations.decrypt(toSort[i], dgk_private));
			}
			else {
				toSort[i] = PaillierCipher.decrypt(toSort[i], paillier_private);
			}
		}
		// Use assert to sort an array
        logger.info("Initial Array: {}", Arrays.toString(toSort));
		Arrays.sort(toSort);
		for (int i = 0; i < min.length; i++) {
			assertEquals(toSort[i], min[i]);
		}
        logger.info("Sorted Array: {}", Arrays.toString(toSort));
        logger.info("Three minimum numbers: {}", Arrays.toString(min));
	}

	public void test_outsourced_multiply(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		Niu.setDGKMode(dgk_mode);
		BigInteger temp;
        logger.info("{}: Testing Multiplication with DGK Mode: {}", alice_class, dgk_mode);
		if(dgk_mode) {
			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(TWO, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 2000);

			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(THREE, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 3000);

			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(FIVE, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 5000);
		}
		else {
			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(TWO, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWO_THOUSAND);

			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(THREE, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), THREE_THOUSAND);

			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(FIFTY, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FIFTY_THOUSAND);
		}
	}

	public void test_outsourced_division(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		// Division Test, Paillier
		// REMEMBER THE OUTPUT IS THE ENCRYPTED ANSWER; ONLY BOB CAN VERIFY THE ANSWER
		Niu.setDGKMode(dgk_mode);
        logger.info("{}: Testing Division, DGK Mode: {}", alice_class, dgk_mode);
		BigInteger d;
		BigInteger temp;
		if (dgk_mode) {
			d = DGKOperations.encrypt(100, dgk_public_key);
		}
		else {
			d = PaillierCipher.encrypt(100, paillier_public);
		}
		temp = Niu.division(d, 2);//100/2 = 50
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 50);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FIFTY);
		}
		temp = Niu.division(d, 3);//100/3 = 33
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 33);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), THIRTY_THREE);
		}
		temp = Niu.division(d, 4);//100/4 = 25
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 25);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWENTY_FIVE);
		}
		temp = Niu.division(d, 5);//100/5 = 20
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 20);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWENTY);
		}
		temp = Niu.division(d, 25);//100/25 = 4
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 4);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FOUR);
		}
	}

	public void test_protocol_one(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Protocol 1 with DGK Mode: {}", alice_class, dgk_mode);
		boolean answer;
		Niu.setDGKMode(dgk_mode);

		// Bob always will compare with a medium
		for(BigInteger l: low) {
			// X <= Y is true
			// logger.info("[Alice] Protocol 1 Testing with {}", l);
			answer = Niu.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is true
			// logger.info("[Alice] Protocol 1 Testing with {}", l);
			answer = Niu.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: high) {
			// X <= Y is false
			// logger.info("[Alice] Protocol 1 Testing with {}", l);
			answer = Niu.Protocol1(l);
			assertFalse(answer);
		}
	}

	public void test_protocol_two(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Protocol 2 with DGK Mode: {}", alice_class, dgk_mode);
		Niu.setDGKMode(dgk_mode);
		boolean answer;

		if (dgk_mode) {
			if (Niu.getClass() != alice.class) {
				for (int i = 0; i < low.length; i++) {
					// Original - Skipped
					// Veugen (X > Y) - false
					// Joye (X >= Y) - false
					answer = Niu.Protocol2(DGKOperations.encrypt(low[i], dgk_public_key),
							DGKOperations.encrypt(mid[i], dgk_public_key));
					assertFalse(answer);


					// Original - Skipped
					// Veugen (X > Y) - false
					// Joye (X >= Y) - true
					answer = Niu.Protocol2(DGKOperations.encrypt(mid[i], dgk_public_key),
							DGKOperations.encrypt(mid[i], dgk_public_key));
					if (Niu.getClass() == alice_joye.class) {
						assertTrue(answer);
					}
					else {
						assertFalse(answer);
					}

					// Original - Skipped
					// Veugen (X > Y) - true
					// Joye (X >= Y) - true
					answer = Niu.Protocol2(DGKOperations.encrypt(high[i], dgk_public_key),
							DGKOperations.encrypt(mid[i], dgk_public_key));
					assertTrue(answer);
				}
			}
		}
		else {
			for (int i = 0; i < low.length;i++) {
				// Original (X >= Y) - false
				// Veugen (X >= Y) - false
				// Joye (X >= Y) - false
				answer = Niu.Protocol2(PaillierCipher.encrypt(low[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertFalse(answer);

				// Original (X >= Y) - true
				// Veugen (X >= Y) - true
				// Joye (X >= Y) - true
				answer = Niu.Protocol2(PaillierCipher.encrypt(mid[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertTrue(answer);

				// Original (X >= Y) - true
				// Veugen (X >= Y) - true
				// Joye (X >= Y) - true
				answer = Niu.Protocol2(PaillierCipher.encrypt(high[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertTrue(answer);
			}
		}
	}

	public void test_private_equality(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Private Equality Check, DGK Mode:{}", alice_class, dgk_mode);
		Niu.setDGKMode(dgk_mode);

		assertFalse(Niu.private_equals(FIFTY));
		assertTrue(Niu.private_equals(FIFTY));
		assertFalse(Niu.private_equals(FIFTY));
	}

	public void test_encrypted_equality(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Encrypted Equality Check, DGK Mode:{}", alice_class, dgk_mode);
		Niu.setDGKMode(dgk_mode);
		BigInteger r_1;
		BigInteger r_2;
		BigInteger r_3;
		BigInteger answer;

		if (dgk_mode) {
			r_1 = DGKOperations.encrypt(FORTY_NINE, dgk_public_key);
			r_2 = DGKOperations.encrypt(FIFTY, dgk_public_key);
			r_3 = DGKOperations.encrypt(FIFTY_ONE, dgk_public_key);
			answer = DGKOperations.encrypt(FIFTY, dgk_public_key);
		}
		else {
			r_1 = PaillierCipher.encrypt(FORTY_NINE, paillier_public);
			r_2 = PaillierCipher.encrypt(FIFTY, paillier_public);
			r_3 = PaillierCipher.encrypt(FIFTY_ONE, paillier_public);
			answer = PaillierCipher.encrypt(FIFTY, paillier_public);
		}
		assertFalse(Niu.encrypted_equals(r_1, answer));
		assertTrue(Niu.encrypted_equals(r_2, answer));
		assertFalse(Niu.encrypted_equals(r_3, answer));
	}
}
