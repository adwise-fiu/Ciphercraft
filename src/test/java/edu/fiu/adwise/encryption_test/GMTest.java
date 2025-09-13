/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.encryption_test;

import org.junit.BeforeClass;
import org.junit.Test;
import edu.fiu.adwise.ciphercraft.gm.GMCipher;
import edu.fiu.adwise.ciphercraft.gm.GMKeyPairGenerator;
import edu.fiu.adwise.ciphercraft.gm.GMPrivateKey;
import edu.fiu.adwise.ciphercraft.gm.GMPublicKey;
import edu.fiu.adwise.ciphercraft.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;

public class GMTest implements constants {
    private static GMPrivateKey private_key;
    private static GMPublicKey public_key;

    @BeforeClass
    public static void generate_keys() {
        GMKeyPairGenerator pa = new GMKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair goldwasser = pa.generateKeyPair();
        public_key = (GMPublicKey) goldwasser.getPublic();
        private_key = (GMPrivateKey) goldwasser.getPrivate();
    }

    @Test
    public void test_decrypt() {
        // Test D(E(X)) = X
        BigInteger [] a = GMCipher.encrypt(BigInteger.TEN, public_key);
        assertEquals(BigInteger.TEN, GMCipher.decrypt(a, private_key));
    }

    @Test
    public void test_xor() throws HomomorphicException {
        // Test D(E(X)) = X
        BigInteger [] a = GMCipher.encrypt(BigInteger.TEN, public_key);

        // Test XOR with array
        BigInteger [] c = GMCipher.xor(a, a, public_key);
        assertEquals(BigInteger.ZERO, GMCipher.decrypt(c, private_key));
    }
}
