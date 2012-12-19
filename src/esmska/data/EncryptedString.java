package esmska.data;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * An encrypted string which can be decrypted on-demand.
 * 
 * @author Martin Pecka
 */
public class EncryptedString
{
    /** The encrypted text. */
    private String cipherText;
    /** The open form of the text. */
    private String plainText = null;

    /**
     * Create an encrypted string with the given cipher.
     * 
     * @param cipherText The ciphertext to use.
     */
    public EncryptedString(String cipherText)
    {
        this.cipherText = cipherText;

        Keyring.getInstance().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                if (e.getID() == Keyring.ACTION_MASTER_PASSWORD_CHANGED) {
                    updateCipherText();
                }

            }
        });
    }

    private EncryptedString(String cipherText, String plainText)
    {
        this(cipherText);
        this.plainText = plainText;
    }

    /**
     * Return the decrypted plaintext.
     * 
     * @return The decrypted plaintext.
     */
    public String getPlainText()
    {
        if (plainText == null && cipherText != null) {
            plainText = Keyring.decrypt(cipherText);
        }

        return plainText;
    }

    /**
     * Return the encrypted ciphertext.
     * 
     * @return The encrypted ciphertext.
     */
    public String getCipherText()
    {
        if (cipherText == null && plainText != null) {
            cipherText = Keyring.encrypt(plainText);
        }
        return cipherText;
    }

    /**
     * Update the ciphertext to reflect the actual master password.
     */
    public void updateCipherText()
    {
        if (plainText == null) {
            cipherText = null;
        } else {
            cipherText = Keyring.encrypt(plainText);
        }

    }

    /**
     * Create an encrypted string using the given plaintext string.
     * 
     * @param plainText The plaintext string.
     * @return The encoded string.
     */
    public static EncryptedString createFromPlainText(String plainText)
    {
        return new EncryptedString(null, plainText);
    }
}
