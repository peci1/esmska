/*
 * ConfigFrame.java
 *
 * Created on 20. červenec 2007, 18:59
 */

package esmska;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.ImageIcon;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import persistence.ConfigBean;

/**
 *
 * @author  ripper
 */
public class ConfigFrame extends javax.swing.JFrame {
    private ConfigBean config;
    
    /** Creates new form ConfigFrame */
    public ConfigFrame(ConfigBean config) {
        this.config = config;
        initComponents();
        useSenderIDCheckBoxActionPerformed(null);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        rememberSettingsCheckBox = new javax.swing.JCheckBox();
        jPanel2 = new javax.swing.JPanel();
        useSenderIDCheckBox = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        senderNumberTextField = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        senderNameTextField = new javax.swing.JTextField();
        closeButton = new javax.swing.JButton();

        setTitle("Nastaven\u00ed");
        setIconImage(new ImageIcon(getClass().getResource("resources/esmska.png")).getImage());
        addWindowFocusListener(new java.awt.event.WindowFocusListener() {
            public void windowGainedFocus(java.awt.event.WindowEvent evt) {
            }
            public void windowLostFocus(java.awt.event.WindowEvent evt) {
                formWindowLostFocus(evt);
            }
        });

        rememberSettingsCheckBox.setSelected(config.isRememberSettings());
        rememberSettingsCheckBox.setText("Pamatovat posledn\u00ed nastaven\u00ed programu");
        rememberSettingsCheckBox.setToolTipText("<html>\nPamatovat posledn\u00ed hodnoty polo\u017eek jednotliv\u00fdch prvk\u016f seznamu.<br>\nP\u0159i ukon\u010den\u00ed programu uchov\u00e1v\u00e1 nap\u0159\u00edklad frontu neodeslan\u00fdch sms, \u010d\u00edslo a jm\u00e9no odesilatele, atd.\n</html>");
        rememberSettingsCheckBox.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 0, 0));
        rememberSettingsCheckBox.setMargin(new java.awt.Insets(0, 0, 0, 0));
        rememberSettingsCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rememberSettingsCheckBoxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(rememberSettingsCheckBox)
                .addContainerGap(66, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(rememberSettingsCheckBox)
                .addContainerGap(139, Short.MAX_VALUE))
        );
        jTabbedPane1.addTab("Obecn\u00e9", jPanel1);

        useSenderIDCheckBox.setSelected(config.isUseSenderID());
        useSenderIDCheckBox.setText("P\u0159ipojovat podpis odesilatele");
        useSenderIDCheckBox.setToolTipText("<html>P\u0159i p\u0159ipojen\u00ed podpisu p\u0159ijde sms adres\u00e1tovi ze zadan\u00e9ho \u010d\u00edsla<br>\na s dan\u00fdm jm\u00e9nem napsan\u00fdm na konci zpr\u00e1vy.</html>");
        useSenderIDCheckBox.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 0, 0));
        useSenderIDCheckBox.setMargin(new java.awt.Insets(0, 0, 0, 0));
        useSenderIDCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                useSenderIDCheckBoxActionPerformed(evt);
            }
        });

        jLabel1.setText("\u010c\u00edslo");

        jLabel2.setText("+420");

        senderNumberTextField.setColumns(9);
        senderNumberTextField.setText(config.getSenderNumber());
        senderNumberTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                senderNumberTextFieldActionPerformed(evt);
            }
        });

        jLabel3.setText("Jm\u00e9no");

        senderNameTextField.setText(config.getSenderName());
        senderNameTextField.setToolTipText("<html>P\u0159i vypln\u011bn\u00ed jm\u00e9na je p\u0159ipojeno na konec zpr\u00e1vy,<br>\ntak\u017ee je sms ve skute\u010dnosti o n\u011bco del\u0161\u00ed.</html>");
        senderNameTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                senderNameTextFieldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(useSenderIDCheckBox)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(17, 17, 17)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel1))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel2Layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(senderNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(senderNameTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 149, Short.MAX_VALUE))))
                .addContainerGap(117, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(useSenderIDCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(senderNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(senderNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(89, Short.MAX_VALUE))
        );
        jTabbedPane1.addTab("Vodafone", jPanel2);

        closeButton.setText("Zav\u0159\u00edt");
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jTabbedPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 352, Short.MAX_VALUE)
                    .addComponent(closeButton))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 193, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(closeButton)
                .addContainerGap())
        );
        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void formWindowLostFocus(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowLostFocus
        senderNameTextFieldActionPerformed(null);
        senderNumberTextFieldActionPerformed(null);
    }//GEN-LAST:event_formWindowLostFocus
    
    private void senderNameTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_senderNameTextFieldActionPerformed
        config.setSenderName(senderNameTextField.getText());
    }//GEN-LAST:event_senderNameTextFieldActionPerformed
    
    private void senderNumberTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_senderNumberTextFieldActionPerformed
        config.setSenderNumber(senderNumberTextField.getText());
    }//GEN-LAST:event_senderNumberTextFieldActionPerformed
    
    private void useSenderIDCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_useSenderIDCheckBoxActionPerformed
        senderNameTextField.setEnabled(useSenderIDCheckBox.isSelected());
        senderNumberTextField.setEnabled(useSenderIDCheckBox.isSelected());
        config.setUseSenderID(useSenderIDCheckBox.isSelected());
    }//GEN-LAST:event_useSenderIDCheckBoxActionPerformed
    
    private void rememberSettingsCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rememberSettingsCheckBoxActionPerformed
        config.setRememberSettings(rememberSettingsCheckBox.isSelected());
    }//GEN-LAST:event_rememberSettingsCheckBoxActionPerformed
    
    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeButtonActionPerformed
        //close form
        this.setVisible(false);
    }//GEN-LAST:event_closeButtonActionPerformed
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton closeButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JCheckBox rememberSettingsCheckBox;
    private javax.swing.JTextField senderNameTextField;
    private javax.swing.JTextField senderNumberTextField;
    private javax.swing.JCheckBox useSenderIDCheckBox;
    // End of variables declaration//GEN-END:variables
    
}