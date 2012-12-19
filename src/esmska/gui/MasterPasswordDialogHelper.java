package esmska.gui;

import java.awt.Component;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import esmska.data.Keyring;
import esmska.utils.L10N;

/**
 * Helper for a dialog for entering master password.
 * 
 * @author Martin Pecka
 * 
 */
public class MasterPasswordDialogHelper {
    
    /** Localization resources. */
    private static final ResourceBundle l10n = L10N.l10nBundle;
    
    /**
     * Show the dialog and ask user to enter the master password.
     * <p>
     * The dialog automatically asks for the password until the user enters the correct master password or until he
     * cancells the dialog.
     * 
     * @param parentComponent The owner of the dialog (may be <code>null</code>).
     * 
     * @return The (correct) master password, or <code>null</code> if user cancelled the dialog.
     */
    public static String show(final Component parentComponent)
    {
        // show the dialog again and again until the user enters correct password (or until he gives up and cancels the
        // dialog)

        // the message to show
        String dialogMessage = l10n.getString("MasterPasswordDialogHelper.enterMasterPassword");
        String dialogTitle = l10n.getString("MasterPasswordDialogHelper.enterMasterPasswordTitle");

        // the loop ends either by cancelling the dialog or by entering correct password
        while (true) {
            final String password = showPasswordDialog(parentComponent, dialogTitle, dialogMessage);

            // user cancelled the dialog, so he doesn't want to enter the password
            if (password == null)
                return null;

            // if the password is correct, we've finished
            if (isPasswordCorrect(password))
                return password;

            // the dialog hasn't been cancelled, but the password is incorrect, so show the dialog again
            dialogMessage = l10n.getString("MasterPasswordDialogHelper.enterMasterPasswordAgain");
            dialogTitle = l10n.getString("MasterPasswordDialogHelper.enterMasterPasswordAgainTitle");
        }
    }

    /**
     * Check, if the given password is the master password.
     * 
     * @param password The password to check.
     * @return True if the password is a master password.
     */
    private static boolean isPasswordCorrect(final String password)
    {
        final Keyring keyring = Keyring.getInstance();
        return keyring.isMasterPassword(password);
    }

    /**
     * Show a modal dialog window with a password prompt.
     * 
     * @param parentComponent Parent component of the dialog.
     * @param dialogTitle Title of the dialog.
     * @param dialogMessage Label of the password dialog.
     * 
     * @return The entered password, or <code>null</code> if user cancelled the dialog.
     */
    private static String showPasswordDialog(Component parentComponent, String dialogTitle, String dialogMessage)
    {
        final JPasswordField passwordField = new JPasswordField();
        final JLabel label = new JLabel(dialogMessage);
        final JOptionPane optionPane = new JOptionPane(new Object[] { label, passwordField },
                JOptionPane.QUESTION_MESSAGE,
                JOptionPane.OK_CANCEL_OPTION);

        final JDialog dialog = optionPane.createDialog(dialogTitle);
        dialog.addWindowFocusListener(new WindowAdapter() {
            @Override
            public void windowGainedFocus(WindowEvent e)
            {
                passwordField.requestFocusInWindow();
            }
        });

        dialog.setVisible(true);
        final int result = (Integer) optionPane.getValue();
        dialog.dispose();

        if (result == JOptionPane.OK_OPTION) {
            return new String(passwordField.getPassword());
        } else {
            return null;
        }
    }
}
