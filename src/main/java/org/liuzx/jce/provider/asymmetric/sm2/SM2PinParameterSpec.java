package org.liuzx.jce.provider.asymmetric.sm2;

import java.security.spec.AlgorithmParameterSpec;

/**
 * A parameter specification for operations requiring a PIN to access an internal private key.
 */
public class SM2PinParameterSpec implements AlgorithmParameterSpec {

    private final char[] pin;

    /**
     * Constructs a parameter spec with the user PIN.
     *
     * @param pin The user PIN for accessing the private key. A copy is made.
     */
    public SM2PinParameterSpec(char[] pin) {
        if (pin == null) {
            throw new IllegalArgumentException("PIN cannot be null.");
        }
        this.pin = pin.clone();
    }

    /**
     * Returns the user PIN.
     *
     * @return A clone of the user PIN.
     */
    public char[] getPin() {
        return pin.clone();
    }
}
