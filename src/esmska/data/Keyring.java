package esmska.data;

import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ObjectUtils;

import esmska.data.event.ActionEventSupport;
import esmska.gui.MasterPasswordDialogHelper;

/**
 * Storage for logins and passwords to gateways.
 * Also offers password encryption and decryption.
 * 
 * @author ripper
 */
public class Keyring
{

    /** The configuration of the program. */
    private static final Config                               config                         = Config.getInstance();

    /** shared instance */
    private static final Keyring                              instance                       = new Keyring();
    /** new key added or existing changed */
    public static final int                                   ACTION_ADD_KEY                 = 0;
    /** existing key removed */
    public static final int                                   ACTION_REMOVE_KEY              = 1;
    /** all keys removed */
    public static final int                                   ACTION_CLEAR_KEYS              = 2;
    /** master password changed */
    public static final int                                   ACTION_MASTER_PASSWORD_CHANGED = 3;
    private static final Logger                               logger                         = Logger.getLogger(Keyring.class
                                                                                                     .getName());
    /** map of [gateway, [login, password]] */
    private final Map<String, Tuple<String, EncryptedString>> keyring                        = Collections
                                                                                                     .synchronizedMap(new HashMap<String, Tuple<String, EncryptedString>>());
    /** manager of the master password */
    private static final MasterPasswordManager                masterPasswordManager;
    // <editor-fold defaultstate="collapsed" desc="ActionEvent support">
    private ActionEventSupport                                actionSupport                  = new ActionEventSupport(
                                                                                                     this);

    public void addActionListener(ActionListener actionListener)
    {
        actionSupport.addActionListener(actionListener);
    }

    public void removeActionListener(ActionListener actionListener)
    {
        actionSupport.removeActionListener(actionListener);
    }

    // </editor-fold>

    static {
        masterPasswordManager = new MasterPasswordManager(config.getMasterPasswordHash());
    }

    /** Private constructor */
    private Keyring()
    {
    }

    /** Get shared instance */
    public static Keyring getInstance()
    {
        return instance;
    }

    /**
     * Get key for chosen gateway.
     * 
     * @param gatewayName Name of the gateway.
     * @return tuple in the form [login, password] if key for this gateway
     *         exists. Null otherwise.
     */
    public Tuple<String, EncryptedString> getKey(String gatewayName)
    {
        return keyring.get(gatewayName);
    }

    /**
     * Put key for chosen gateway. If a key for this gateway already exists,
     * overwrite previous one.
     * 
     * @param gatewayName Name of the gateway.
     * @param key tuple in the form [login, password].
     * @throws IllegalArgumentException If gatewayName or key is null.
     */
    public void putKey(String gatewayName, Tuple<String, EncryptedString> key)
    {
        if (putKeyImpl(gatewayName, key)) {
            logger.finer("New keyring key added: [gatewayName=" + gatewayName + "]");
            actionSupport.fireActionPerformed(ACTION_ADD_KEY, null);
        }
    }

    /** Inner execution code for putKey method
     * @return true if keyring was updated (key was not present or was modified
     * by the update); false if nothing has changed
     */
    private boolean putKeyImpl(String gatewayName, Tuple<String, EncryptedString> key)
    {
        if (gatewayName == null) {
            throw new IllegalArgumentException("gatewayName");
        }
        if (key == null) {
            throw new IllegalArgumentException("key");
        }
        Tuple<String, EncryptedString> previous = keyring.put(gatewayName, key);
        return previous == null || !ObjectUtils.equals(previous, key);
    }

    /** Put keys for more gateways. If a key for particular gateway already exists,
     * overwrite previous one.
     * @param keys Map in the form [gatewayName, Key], where Key is in the
     *             form [login, password].
     * @throws IllegalArgumentException If some gatewayName or some key is null.
     */
    public void putKeys(Map<String, Tuple<String, EncryptedString>> keys)
    {
        int changed = 0;
        for (Entry<String, Tuple<String, EncryptedString>> entry : keys.entrySet()) {
            changed += putKeyImpl(entry.getKey(), entry.getValue()) ? 1 : 0;
        }
        if (changed > 0) {
            logger.finer(changed + " new keyring keys added");
            actionSupport.fireActionPerformed(ACTION_ADD_KEY, null);
        }
    }

    /** Remove chosen gateway from the keyring.
     * @param gatewayName Name of the gateway.
     */
    public void removeKey(String gatewayName) {
        if (keyring.remove(gatewayName) != null) {
            logger.finer("A keyring key removed: [gatewayName=" + gatewayName + "]");
            actionSupport.fireActionPerformed(ACTION_REMOVE_KEY, null);
        }
    }

    /** Get set of all gateway names, which are in the keyring.
     * @return Unmodifiable set of all gateway names, which are in the keyring.
     */
    public Set<String> getGatewayNames() {
        return Collections.unmodifiableSet(keyring.keySet());
    }

    /** Clear all gateway names and corresponding keys from the keyring.
     * The keyring will be empty after this.
     */
    public void clearKeys() {
        keyring.clear();
        logger.finer("All keyring keys removed");
        actionSupport.fireActionPerformed(ACTION_CLEAR_KEYS, null);
    }

    /** Encrypt input string. The string is encrypted using XOR encryption with
     * internal passphrase, doubled and the result is encoded using the Base64 encoding.
     * @param input Input string. Null is transformed to empty string.
     * @return Encrypted string 
     */
    public static String encrypt(String input) {
        if (input == null) {
            input = "";
        }

        try {
            byte[] inputArray = input.getBytes("UTF-8");
            byte[] encrArray = new byte[inputArray.length*2];

            final byte[] passphrase = masterPasswordManager.getMasterPassword();
            if (passphrase == null) {
                throw new IllegalStateException("The master password wasn't provided to encode the string.");
            }

            for (int i = 0; i < inputArray.length; i++) {
                byte k = i < passphrase.length ? passphrase[i] : 0;
                encrArray[2*i] = (byte) (inputArray[i] ^ k);
                //let's double the string, if hides too short password lengths
                encrArray[2*i+1] = encrArray[2*i];
            }

            String encrString = new String(Base64.encodeBase64(encrArray), "US-ASCII");
            return encrString;
        } catch (UnsupportedEncodingException ex) {
            assert false : "Basic charsets must be supported";
            throw new IllegalStateException("Basic charsets must be supported", ex);
        }
    }

    /** Decrypt input string. The input string is decoded using the Base64 encoding,
     * halved, and the result is decrypted using XOR encryption with internal passphrase.
     * @param input Input string. The input must originate from the encrypt() function.
     *              Null is transformed to empty string.
     * @return Decrypted string.
     */
    public static String decrypt(String input) {
        if (input == null) {
            input = "";
        }

        try {
            byte[] encrArray = Base64.decodeBase64(input.getBytes("US-ASCII"));
            byte[] decrArray = new byte[encrArray.length/2];

            final byte[] passphrase = masterPasswordManager.getMasterPassword();
            if (passphrase == null) {
                throw new IllegalStateException("The master password wasn't provided to decode the string.");
            }

            for (int i = 0; i < encrArray.length; i+=2) {
                byte k = i/2 < passphrase.length ? passphrase[i/2] : 0;
                //array must be halved, encrypted is doubled
                decrArray[i/2] = (byte) (encrArray[i] ^ k);
            }

            String decrString = new String(decrArray, "UTF-8");
            return decrString;
        } catch (UnsupportedEncodingException ex) {
            assert false : "Basic charsets must be supported";
            throw new IllegalStateException("Basic charsets must be supported", ex);
        }
    }

    /**
     * Return true if the given password is the master password.
     * 
     * @param password The password to check.
     * @return true if the given password is the master password.
     */
    public boolean isMasterPassword(final String password)
    {
        return masterPasswordManager.isMasterPassword(password);
    }

    /**
     * Set a new master password.
     * <p>
     * Requires that the previous master PW (if used) has been already entered.
     * 
     * @param password The password to set.
     */
    public void setMasterPasswordString(final String password)
    {
        if (masterPasswordManager.setMasterPasswordString(password)) {

            // update the ciphertexts for all saved passwords
            for (Entry<String, Tuple<String, EncryptedString>> entry : keyring.entrySet()) {
                entry.getValue().get2().updateCipherText();
            }

            actionSupport.fireActionPerformed(ACTION_MASTER_PASSWORD_CHANGED, null);
        }
    }

    /**
     * Manager of the master password.
     * 
     * @author Martin Pecka
     */
    private static final class MasterPasswordManager
    {
        /** Hash of the password. <code>null</code> if no password is set. */
        private byte[]       masterPasswordHash = null;

        /** The master password. <code>null</code> if the password hasn't been entered yet. */
        private byte[]       masterPassword     = null;

        /** randomly generated passphrase */
        private final byte[] defaultPassphrase  = new byte[] { -47, 12, -115, -66, 28, 102, 93, 101, -98, -87, 96, -11,
                                                        -72, 117, -39, 39, 102, 73, -122, 91, -14, -118, 5, -82, -126,
                                                        3, 38, -19, -63, -127, 46, -82, 27, -38, -89, 29, 10, 81, -108,
                                                        17, -96, -71, 120, 63, -128, -3, -3, -63, 65, -40, 109, 70, 69,
                                                        -122, 80, -83, 37, -45, 61, 60, -12, -101, 0, -126, 44, -125,
                                                        -83, 47, -48, -7, 8, 16, 127, 25, -1, -23, 27, -78, 124, 36,
                                                        59, 52, -66, 40, -31, -7, 111, -101, -5, 85, -65, -90, -56,
                                                        -51, 53, 44, 20, 15, 111, 37, -97, 120, -60, 53, -80, 69, 34,
                                                        109, -71, 101, -66, 77, 52, -14, 112, 112, 97, 12, -76, -96,
                                                        -101, 103, -59, 38, -24, -10, -85, -119 };

        /**
         * Create the password manager using the given master password hash.
         * 
         * @param masterPasswordHash SHA1 hash of the master password, or <code>null</code> if no master password is
         *            used.
         */
        public MasterPasswordManager(byte[] masterPasswordHash)
        {
            this.masterPasswordHash = masterPasswordHash;
        }

        /**
         * Get the master password. If it hasn't been entered yet, a dialog is shown asking for typing in the password.
         * 
         * @return The master password as a byte array. <code>null</code> if user refuses to enter the password.
         */
        public byte[] getMasterPassword()
        {
            // no master password is set
            if (masterPasswordHash == null)
                return defaultPassphrase;

            // master password is set but we need to request it
            if (masterPassword == null) {
                // show a dialog for entering the master password
                final String masterPasswordString = MasterPasswordDialogHelper.show(null);

                // masterPasswordString here has to contain the correct master password (see
                // MasterPasswordDialogHelper#show() )
                setMasterPasswordStringImpl(masterPasswordString);

                // if masterPasswordString is null, user cancelled entering the password and we don't have any password
                // to use
            }

            return masterPassword;
        }

        /**
         * Return true if the given password is the master password.
         * 
         * @param password The password to check.
         * @return true if the given password is the master password.
         */
        public boolean isMasterPassword(final String password)
        {
            synchronized (masterPasswordHash) {
                if (masterPasswordHash == null || password == null)
                    return false;

                final byte[] digest = hashPasswordString(password);

                return Arrays.equals(digest, masterPasswordHash);
            }
        }

        /**
         * Return the hash of the given password.
         * 
         * @param password The password to hash.
         * @return Hash of the password.
         */
        public byte[] hashPasswordString(String password)
        {
            return DigestUtils.sha(password);
        }

        /**
         * Set the string denoting the master password. The saved hash is updated automatically.
         * 
         * @param masterPasswordString The masterPasswordString to set. Pass <code>null</code> to use the default
         *            password.
         * 
         * @retrurn Return true if the given password is different than the old password.
         * 
         * @throws IllegalStateException If the master password hasn't been entered yet.
         */
        public synchronized boolean setMasterPasswordString(String masterPasswordString) throws IllegalStateException
        {
            if (masterPassword == null && masterPasswordHash != null)
                throw new IllegalStateException("Cannot change master password before it was entered.");

            // do not run the setters when both the old and new passwords are null
            if (masterPasswordHash != null || masterPasswordString != null) {
                setMasterPasswordStringImpl(masterPasswordString);
                return setMasterPasswordHashFromString(masterPasswordString);
            } else {
                return false;
            }
        }

        /**
         * Compute and save the password hash from the given string.
         * 
         * @param masterPasswordString The password to compute hash for.
         * 
         * @return Return true if the given password has a different hash than the current one.
         */
        private synchronized boolean setMasterPasswordHashFromString(String masterPasswordString)
        {
            final byte[] oldHash = masterPasswordHash;

            if (masterPasswordString == null) {
                masterPasswordHash = null;
            } else {
                masterPasswordHash = hashPasswordString(masterPasswordString);
            }

            config.setMasterPasswordHash(masterPasswordHash);

            if (oldHash != null) {
                if (masterPasswordHash == null)
                    return true;
                else
                    return !Arrays.equals(oldHash, masterPasswordHash);
            } else {
                return masterPasswordHash != null;
            }
        }

        /**
         * Set the string denoting the master password. The saved hash is not updated.
         * 
         * @param masterPasswordString The masterPasswordString to set. Pass <code>null</code> to use the default
         *            password or to "forget" the current master PW (depending on whether {@link #masterPasswordHash} is
         *            <code>null</code>).
         */
        private synchronized void setMasterPasswordStringImpl(String masterPasswordString)
        {
            if (masterPasswordString == null) {
                masterPassword = null;
            } else {
                // copy the password into masterPassword filling the remaining space with bits from the default
                // password (so that masterPassword will have its length greater or equal to the length of the
                // default password)
                final byte[] password = masterPasswordString.getBytes();
                masterPassword = new byte[Math.max(defaultPassphrase.length, password.length)];
                for (int i = 0; i < masterPassword.length; i++) {
                    if (i < password.length) {
                        masterPassword[i] = password[i];
                    } else {
                        assert i < defaultPassphrase.length;
                        masterPassword[i] = defaultPassphrase[i];
                    }
                }
            }
        }
    }
}
