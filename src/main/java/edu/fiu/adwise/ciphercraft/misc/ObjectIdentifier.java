package edu.fiu.adwise.ciphercraft.misc;

import edu.fiu.adwise.ciphercraft.dgk.DGK_Key;
import edu.fiu.adwise.ciphercraft.elgamal.ElGamal_Key;
import edu.fiu.adwise.ciphercraft.gm.GMKey;
import edu.fiu.adwise.ciphercraft.paillier.PaillierKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.Key;

public class ObjectIdentifier {

    /**
     * The Object Identifier (OID) for a VCU-specific cryptographic algorithm.
     * <p>
     * An OID is a globally unique identifier with a hierarchical structure.
     * The prefix {@code 1.3.6.1.4.1} is the globally recognized path for **Private Enterprise Numbers (PENs)**.
     * <ul>
     * <li>{@code 1}: Refers to ISO (International Organization for Standardization).</li>
     * <li>{@code 3}: A sub-tree for "identified-organization."</li>
     * <li>{@code 6}: A sub-tree for the U.S. Department of Defense (DoD).</li>
     * <li>{@code 1}: The "internet" branch under the DoD.</li>
     * <li>{@code 4}: The "private" branch for privately assigned numbers.</li>
     * <li>{@code 1}: The "enterprise" branch, which IANA manages for PENs.</li>
     * </ul>
     * <p>
     * The number {@code 10384} is the specific PEN assigned to Virginia Commonwealth University (VCU)
     * by the Internet Assigned Numbers Authority (IANA). The final number, {@code 1}, is a
     * sub-identifier defined by VCU for DGK, and the sequence continues for ElGamal, Goldwasser-Micali and Paillier.
     * <p>
     * You can verify this assignment on the official IANA registry here:
     * {@link <a href="https://www.iana.org/assignments/enterprise-numbers">IANA Link</a>}.
     * @param key the cryptographic key instance
     * @return the corresponding ASN1ObjectIdentifier for the algorithm, or {@code null} if unknown
     */
    public static ASN1ObjectIdentifier getAlgorithm(Key key) {
        if (key instanceof DGK_Key) {
            return new ASN1ObjectIdentifier("1.3.6.1.4.1.10384.1");
        }
        else if (key instanceof ElGamal_Key) {
            return new ASN1ObjectIdentifier("1.3.6.1.4.1.10384.2");
        }
        else if (key instanceof GMKey) {
            return new ASN1ObjectIdentifier("1.3.6.1.4.1.10384.3");
        }
        else if (key instanceof PaillierKey) {
            return new ASN1ObjectIdentifier("1.3.6.1.4.1.10384.4");
        }
        else {
            return null;
        }
    }
}
