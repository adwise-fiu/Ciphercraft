/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.ciphercraft.misc;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Base64;

import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.*;
import static edu.fiu.adwise.ciphercraft.misc.CipherConstants.PRIVATE_KEY_END;

/**
 * Utility class for reading and writing cryptographic keys in PEM format.
 * <p>
 * Provides methods to serialize {@link java.security.Key} objects to PEM files
 * and to parse PEM-encoded key files into byte arrays.
 * <p>
 * This class supports both public and private keys, automatically handling
 * the appropriate PEM headers and footers.
 */
public class KeyFunctions {

    /**
     * Writes the key to a file in PEM format.
     * @param key The key to write
     * @param key_file The file path to save the public key.
     * @throws IOException If an I/O error occurs.
     */
    public static void writeKey(Key key, String key_file) throws IOException {
        String pem;
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
        if (key instanceof PublicKey) {
            pem = PUBLIC_KEY_START + "\n" + base64 + "\n" + PUBLIC_KEY_END + "\n";
        }
        else {
            pem = PRIVATE_KEY_START + "\n" + base64 + "\n" + PRIVATE_KEY_END + "\n";
        }
        try (FileWriter fw = new FileWriter(key_file)) {
            fw.write(pem);
        }
    }

    /**
     * Reads a PEM-encoded key from a file and decodes its Base64 content.
     *
     * @param filePath the path to the PEM file
     * @param beginMarker the string marking the beginning of the key section (e.g., "-----BEGIN PUBLIC KEY-----")
     * @param endMarker the string marking the end of the key section (e.g., "-----END PUBLIC KEY-----")
     * @return a byte array containing the decoded key data
     * @throws IOException if an I/O error occurs while reading the file
     */
    public static byte[] readPemFile(String filePath, String beginMarker, String endMarker) throws IOException {
        StringBuilder pemContent = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            boolean inKey = false;
            while ((line = br.readLine()) != null) {
                if (line.contains(beginMarker)) {
                    inKey = true;
                    continue;
                }
                if (line.contains(endMarker)) {
                    break;
                }
                if (inKey) {
                    pemContent.append(line.trim());
                }
            }
        }
        return Base64.getMimeDecoder().decode(pemContent.toString());
    }
}
