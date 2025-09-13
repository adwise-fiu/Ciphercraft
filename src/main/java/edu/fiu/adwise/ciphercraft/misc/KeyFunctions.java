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
