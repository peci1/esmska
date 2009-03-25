/*
 * StatusPanel.java
 *
 * Created on 4. leden 2008, 23:27
 */
package esmska.gui;

import esmska.data.Log;
import esmska.utils.L10N;
import esmska.utils.Workarounds;
import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.DateFormat;
import java.util.Date;
import java.util.ResourceBundle;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.Timer;
import org.openide.awt.Mnemonics;

/** Status bar panel
 *
 * @author  ripper
 */
public class StatusPanel extends javax.swing.JPanel {

    private static final String RES = "/esmska/resources/";
    private static final ResourceBundle l10n = L10N.l10nBundle;
    private static final DateFormat shortTimeFormat = DateFormat.getTimeInstance(DateFormat.SHORT);
    private Log log = Log.getInstance();
    private Timer statusTimer = new Timer(5000, new HideStatusListener());
    private Runnable currentHandler;
    
    /** Creates new form StatusPanel */
    public StatusPanel() {
        initComponents();
        statusTimer.setRepeats(false);

        //listen for changes in log and display last record
        log.addActionListener(new LogListener());
    }

    /** Prints message to status bar
     *
     * @param message text
     * @param time show timestamp before text. Use null for no timestamp.
     * @param icon show icon with text. Use null for no icon.
     * @param html if there are html tags inside the text. Even if this is true,
     * the text should not contain &lt;html&gt; start and end tags.
     */
    public void setStatusMessage(String message, Date time, ImageIcon icon, boolean html) {
        String messageEsc = message;
        if (!html) {
            messageEsc = Workarounds.escapeHtml(message);
        }
        if (time != null) {
            String timestamp = shortTimeFormat.format(time);
            statusMessageLabel.setText("<html>[" + timestamp + "] " + messageEsc + "</html>");
        } else {
            statusMessageLabel.setText("<html>" + messageEsc + "</html>");
        }
        statusMessageLabel.setIcon(icon);
        //reset handler
        currentHandler = null;
        statusMessageLabel.setToolTipText(l10n.getString("StatusPanel.statusMessageLabel.toolTipText"));
    }

    /** Add handler to mouse click on the log message. The handler will be removed
     * after another log message is shown.
     * @param handler handler to execute
     * @param tooltip tooltip for mouse-over, may be null
     */
    public void installClickHandler(Runnable handler, String tooltip) {
        currentHandler = handler;
        statusMessageLabel.setToolTipText(tooltip);
    }
    
    /** Hide current status message after specified time. If new status message
     *  is displayed in the meantime, this scheduled action is cancelled.
     * @param millis time in milliseconds. Use 0 or negative number to cancel the timer.
     */
    public void hideStatusMessageAfter(int millis) {
        if (millis <= 0) {
            statusTimer.stop();
            return;
        }
        statusTimer.setInitialDelay(millis);
        statusTimer.restart();
    }

    /** Tells main form whether it should display task busy icon */
    public void setTaskRunning(boolean b) {
        if (b == false) {
            statusAnimationLabel.setIcon(new ImageIcon(getClass().getResource(RES + "task-idle.png")));
        } else {
            statusAnimationLabel.setIcon(new ImageIcon(getClass().getResource(RES + "task-busy.gif")));
        }
    }

    /** Set progress on progress bar
     * Use null to any parameter if you don't want to set it
     */
    public void setProgress(Integer value, String text, Boolean stringPainted, Boolean visible) {
        if (value != null) {
            progressBar.setValue(value);
        }
        if (text != null) {
            progressBar.setString(text);
        }
        if (stringPainted != null) {
            progressBar.setStringPainted(stringPainted);
        }
        if (visible != null) {
            progressBar.setVisible(visible);
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        statusMessageLabel = new JLabel();
        statusAnimationLabel = new JLabel();
        progressBar = new JProgressBar();

        Mnemonics.setLocalizedText(statusMessageLabel, l10n.getString("StatusPanel.statusMessageLabel.text")); // NOI18N
        statusMessageLabel.setToolTipText(l10n.getString("StatusPanel.statusMessageLabel.toolTipText")); // NOI18N
        statusMessageLabel.setFocusable(false);
        statusMessageLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        statusMessageLabel.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent evt) {
                statusMessageLabelMouseClicked(evt);
            }
        });

        statusAnimationLabel.setIcon(new ImageIcon(getClass().getResource("/esmska/resources/task-idle.png"))); // NOI18N
        statusAnimationLabel.setFocusable(false);

        progressBar.setMaximum(15);
        progressBar.setFocusable(false);
        progressBar.setString(l10n.getString("StatusPanel.progressBar.string")); // NOI18N
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(Alignment.LEADING)
            .addGroup(Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusMessageLabel, GroupLayout.DEFAULT_SIZE, 163, Short.MAX_VALUE)
                .addPreferredGap(ComponentPlacement.RELATED)
                .addComponent(progressBar, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel, GroupLayout.PREFERRED_SIZE, 16, GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(Alignment.LEADING)
            .addComponent(statusMessageLabel, Alignment.TRAILING, GroupLayout.DEFAULT_SIZE, 20, Short.MAX_VALUE)
            .addComponent(statusAnimationLabel, Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE)
            .addComponent(progressBar, Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void statusMessageLabelMouseClicked(MouseEvent evt) {//GEN-FIRST:event_statusMessageLabelMouseClicked
        if (currentHandler != null) {
            currentHandler.run();
        } else {
            Actions.getLogAction().actionPerformed(null);
        }
    }//GEN-LAST:event_statusMessageLabelMouseClicked

    /** Listen for log changes */
    private class LogListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getID() == Log.ACTION_ADD_RECORD) {
                Log.Record last = log.getLastRecord();
                setStatusMessage(last.getMessage(), last.getTime(), last.getIcon(), false);
            }
        }
    }

    /** Hide all information in status message label */
    private class HideStatusListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            statusMessageLabel.setIcon(null);
            statusMessageLabel.setText(null);
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private JProgressBar progressBar;
    private JLabel statusAnimationLabel;
    private JLabel statusMessageLabel;
    // End of variables declaration//GEN-END:variables
}
