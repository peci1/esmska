/*
 * QueuePanel.java
 *
 * Created on 3. říjen 2007, 22:05
 */

package esmska.gui;

import esmska.data.Config;
import esmska.data.Icons;
import esmska.data.SMS;
import esmska.operators.Operator;
import esmska.operators.OperatorUtil;
import esmska.persistence.PersistenceManager;
import esmska.utils.ActionEventSupport;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.Collections;
import java.util.List;
import javax.swing.AbstractAction;
import javax.swing.AbstractListModel;
import javax.swing.Action;
import javax.swing.DefaultListCellRenderer;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JList;
import org.jvnet.substance.SubstanceLookAndFeel;

/** SMS queue panel
 *
 * @author  ripper
 */
public class QueuePanel extends javax.swing.JPanel {
    public static final int ACTION_REQUEST_EDIT_SMS = 0;
    public static final int ACTION_QUEUE_PAUSE_CHANGED = 1;
    
    private static final String RES = "/esmska/resources/";
    private List<SMS> smsQueue = PersistenceManager.getQueue();
    private Config config = PersistenceManager.getConfig();
    
    private SMSQueuePauseAction smsQueuePauseAction = new SMSQueuePauseAction();
    private Action deleteSMSAction = new DeleteSMSAction();
    private Action editSMSAction = new EditSMSAction();
    private Action smsUpAction = new SMSUpAction();
    private Action smsDownAction = new SMSDownAction();
    private SMSQueueListModel smsQueueListModel = new SMSQueueListModel();
    
    private SMS editRequestedSMS;
    
    // <editor-fold defaultstate="collapsed" desc="ActionEvent support">
    private ActionEventSupport actionSupport = new ActionEventSupport(this);
    public void addActionListener(ActionListener actionListener) {
        actionSupport.addActionListener(actionListener);
    }
    
    public void removeActionListener(ActionListener actionListener) {
        actionSupport.removeActionListener(actionListener);
    }
    // </editor-fold>
    
    /** Creates new form QueuePanel */
    public QueuePanel() {
        initComponents();
    }
    
    /** Get SMS which was requested to be edited */
    public SMS getEditRequestedSMS() {
        return editRequestedSMS;
    }
    
    /** Whether queue is currently paused */
    public boolean isPaused() {
        return smsQueuePauseAction.isPaused();
    }
    
    /** Sets whether queue is currently paused */
    public void setPaused(boolean paused) {
        smsQueuePauseAction.setPaused(paused);
    }
    
    /** Updates status of selected SMS */
    public void smsProcessed(SMS sms) {
        int index = smsQueueListModel.indexOf(sms);
        if (sms.getStatus() == SMS.Status.SENT_OK) {
            smsQueueListModel.remove(sms);
        }
        if (sms.getStatus() == SMS.Status.PROBLEMATIC) {
            smsQueueListModel.fireContentsChanged(
                    smsQueueListModel, index, index);
        }
    }
    
    /** Adds new SMS to the queue */
    public void addSMS(SMS sms) {
        smsQueueListModel.add(sms);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        smsUpButton = new javax.swing.JButton();
        smsDownButton = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        smsQueueList = new javax.swing.JList();
        editButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();
        pauseButton = new javax.swing.JToggleButton();

        setBorder(javax.swing.BorderFactory.createTitledBorder("Fronta"));
        addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                formFocusGained(evt);
            }
        });

        smsUpButton.setAction(smsUpAction);
        smsUpButton.setMargin(new java.awt.Insets(2, 2, 2, 2));
        smsUpButton.putClientProperty(SubstanceLookAndFeel.FLAT_PROPERTY, Boolean.TRUE);

        smsDownButton.setAction(smsDownAction);
        smsDownButton.setMargin(new java.awt.Insets(2, 2, 2, 2));
        smsDownButton.putClientProperty(SubstanceLookAndFeel.FLAT_PROPERTY, Boolean.TRUE);

        smsQueueList.setModel(smsQueueListModel);
        smsQueueList.setCellRenderer(new SMSQueueListRenderer());
        smsQueueList.setVisibleRowCount(4);
        smsQueueList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                smsQueueListValueChanged(evt);
            }
        });
        jScrollPane2.setViewportView(smsQueueList);

        editButton.setAction(editSMSAction);
        editButton.setMargin(new java.awt.Insets(2, 2, 2, 2));
        editButton.putClientProperty(SubstanceLookAndFeel.FLAT_PROPERTY, Boolean.TRUE);

        deleteButton.setAction(deleteSMSAction);
        deleteButton.setMargin(new java.awt.Insets(2, 2, 2, 2));
        deleteButton.putClientProperty(SubstanceLookAndFeel.FLAT_PROPERTY, Boolean.TRUE);

        pauseButton.setAction(smsQueuePauseAction);
        pauseButton.setMargin(new java.awt.Insets(2, 2, 2, 2));
        pauseButton.putClientProperty(SubstanceLookAndFeel.FLAT_PROPERTY, Boolean.TRUE);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(smsDownButton)
                    .addComponent(smsUpButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 181, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(deleteButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pauseButton))
                    .addComponent(editButton))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {deleteButton, editButton, pauseButton, smsDownButton, smsUpButton});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.LEADING, 0, 0, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(pauseButton))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(smsUpButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(smsDownButton))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(editButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(deleteButton)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {deleteButton, editButton, pauseButton, smsDownButton, smsUpButton});

    }// </editor-fold>//GEN-END:initComponents
    
    private void smsQueueListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_smsQueueListValueChanged
        //update form components
        if (!evt.getValueIsAdjusting()) {
            int queueSize = smsQueueListModel.getSize();
            int selectedItems = smsQueueList.getSelectedIndices().length;
            deleteSMSAction.setEnabled(queueSize != 0 && selectedItems != 0);
            editSMSAction.setEnabled(queueSize != 0 && selectedItems == 1);
            smsUpAction.setEnabled(queueSize != 0 && selectedItems == 1);
            smsDownAction.setEnabled(queueSize != 0 && selectedItems == 1);
        }
    }//GEN-LAST:event_smsQueueListValueChanged

    private void formFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_formFocusGained
        pauseButton.requestFocusInWindow();
    }//GEN-LAST:event_formFocusGained
    
    /** Erase sms from queue list */
    private class DeleteSMSAction extends AbstractAction {
        public DeleteSMSAction() {
            super(null, new ImageIcon(QueuePanel.class.getResource(RES + "delete.png")));
            this.putValue(SHORT_DESCRIPTION,"Odstranit označené zprávy");
            this.setEnabled(false);
        }
        @Override
        public void actionPerformed(ActionEvent e) {
            Object[] smsArray = smsQueueList.getSelectedValues();
            for (Object o : smsArray) {
                SMS sms = (SMS) o;
                smsQueueListModel.remove(sms);
            }
            //transfer focus
            if (smsQueueListModel.getSize() > 0)
                smsQueueList.requestFocusInWindow();
            else
                pauseButton.requestFocusInWindow();
        }
    }
    
    /** Edit sms from queue */
    private class EditSMSAction extends AbstractAction {
        public EditSMSAction() {
            super(null, new ImageIcon(QueuePanel.class.getResource(RES + "edit-22.png")));
            this.putValue(SHORT_DESCRIPTION,"Upravit označenou zprávu");
            this.setEnabled(false);
        }
        @Override
        public void actionPerformed(ActionEvent e) {
            SMS sms = (SMS) smsQueueList.getSelectedValue();
            if (sms == null)
                return;
            
            editRequestedSMS = sms;
            smsQueueListModel.remove(sms);
            
            //fire event
            actionSupport.fireActionPerformed(ACTION_REQUEST_EDIT_SMS, null);
        }
    }
    
    /** move sms up in sms queue */
    private class SMSUpAction extends AbstractAction {
        public SMSUpAction() {
            super(null,new ImageIcon(QueuePanel.class.getResource(RES + "up.png")));
            this.putValue(SHORT_DESCRIPTION,"Posunout sms ve frontě výše");
            this.setEnabled(false);
        }
        @Override
        public void actionPerformed(ActionEvent e) {
            int index = smsQueueList.getSelectedIndex();
            if (index <= 0) //cannot move up first item
                return;
            synchronized(smsQueue) {
                Collections.swap(smsQueue,index,index-1);
            }
            smsQueueListModel.fireContentsChanged(
                    smsQueueListModel, index-1, index);
            smsQueueList.setSelectedIndex(index-1);
            smsQueueList.ensureIndexIsVisible(index-1);
        }
    }
    
    /** move sms down in sms queue */
    private class SMSDownAction extends AbstractAction {
        public SMSDownAction() {
            super(null,new ImageIcon(QueuePanel.class.getResource(RES + "down.png")));
            this.putValue(SHORT_DESCRIPTION,"Posunout sms ve frontě níže");
            this.setEnabled(false);
        }
        @Override
        public void actionPerformed(ActionEvent e) {
            int index = smsQueueList.getSelectedIndex();
            if (index < 0 || index >= smsQueueListModel.getSize() - 1) //cannot move down last item
                return;
            synchronized(smsQueue) {
                Collections.swap(smsQueue,index,index+1);
            }
            smsQueueListModel.fireContentsChanged(
                    smsQueueListModel, index, index+1);
            smsQueueList.setSelectedIndex(index+1);
            smsQueueList.ensureIndexIsVisible(index+1);
        }
    }
    
    /** Pause/unpause the sms queue */
    private class SMSQueuePauseAction extends AbstractAction {
        private boolean paused = false;
        private final String descRunning = "Pozastavit odesílání sms ve frontě (Alt+P)";
        private final String descStopped = "Pokračovat v odesílání sms ve frontě (Alt+P)";
        private final ImageIcon pauseIcon = new ImageIcon(QueuePanel.class.getResource(RES + "pause.png"));
        private final ImageIcon startIcon = new ImageIcon(QueuePanel.class.getResource(RES + "start.png"));
        public SMSQueuePauseAction() {
            super(null, new ImageIcon(QueuePanel.class.getResource(RES + "pause.png")));
            putValue(SHORT_DESCRIPTION,descRunning);
            putValue(MNEMONIC_KEY, KeyEvent.VK_P);
            putValue(SELECTED_KEY, false);
        }
        @Override
        public void actionPerformed(ActionEvent e) {
            if (paused) {
                putValue(LARGE_ICON_KEY,pauseIcon);
                putValue(SHORT_DESCRIPTION,descRunning);
                putValue(SELECTED_KEY, false);
            } else {
                putValue(LARGE_ICON_KEY, startIcon);
                putValue(SHORT_DESCRIPTION,descStopped);
                putValue(SELECTED_KEY, true);
            }
            paused = !paused;
            
            //fire event
            actionSupport.fireActionPerformed(ACTION_QUEUE_PAUSE_CHANGED, null);
        }
        public boolean isPaused() {
            return paused;
        }
        public void setPaused(boolean paused) {
            //set opposite because actionPerformed will revert it
            this.paused = !paused;
            actionPerformed(null);
        }
    }
    
    /** get action used to pause/unpause the sms queue */
    public Action getSMSQueuePauseAction() {
        return smsQueuePauseAction;
    }
    
    /** Model for SMSQueueList */
    private class SMSQueueListModel extends AbstractListModel {
        @Override
        public SMS getElementAt(int index) {
            return smsQueue.get(index);
        }
        @Override
        public int getSize() {
            return smsQueue.size();
        }
        public int indexOf(SMS element) {
            return smsQueue.indexOf(element);
        }
        public void add(SMS element) {
            if (smsQueue.add(element)) {
                int index = smsQueue.indexOf(element);
                fireIntervalAdded(this, index, index);
            }
        }
        public boolean contains(SMS element) {
            return smsQueue.contains(element);
        }
        public boolean remove(SMS element) {
            int index = smsQueue.indexOf(element);
            boolean removed = smsQueue.remove(element);
            if (removed) {
                fireIntervalRemoved(this, index, index);
            }
            return removed;
        }
        @Override
        protected void fireIntervalRemoved(Object source, int index0, int index1) {
            super.fireIntervalRemoved(source, index0, index1);
        }
        @Override
        protected void fireIntervalAdded(Object source, int index0, int index1) {
            super.fireIntervalAdded(source, index0, index1);
        }
        @Override
        protected void fireContentsChanged(Object source, int index0, int index1) {
            super.fireContentsChanged(source, index0, index1);
        }
    }
    
    /** Renderer for items in queue list */
    private class SMSQueueListRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            Component c = super.getListCellRendererComponent(list,value,index,isSelected,cellHasFocus);
            SMS sms = (SMS)value;
            
            //set text
            String text = sms.toString();
            if (text.startsWith(config.getCountryPrefix()))
                text = text.substring(config.getCountryPrefix().length());
            ((JLabel)c).setText(text);
            //problematic sms colored
            if ((sms.getStatus() == SMS.Status.PROBLEMATIC) && !isSelected) {
                c.setBackground(Color.RED);
            }
            //add operator logo
            Operator operator = OperatorUtil.getOperator(sms.getOperator());
            ((JLabel)c).setIcon(operator != null ? operator.getIcon() : Icons.OPERATOR_BLANK);
            //set tooltip
            ((JLabel)c).setToolTipText(wrapToHTML(sms.getText()));
            
            return c;
        }
        /** transform string to html with linebreaks */
        private String wrapToHTML(String text) {
            StringBuilder output = new StringBuilder();
            output.append("<html>");
            int from = 0;
            while (from < text.length()) {
                int to = from + 50;
                to = text.indexOf(' ',to);
                if (to < 0)
                    to = text.length();
                output.append(text.substring(from, to));
                output.append("<br>");
                from = to + 1;
            }
            output.append("</html>");
            return output.toString();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton deleteButton;
    private javax.swing.JButton editButton;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JToggleButton pauseButton;
    private javax.swing.JButton smsDownButton;
    private javax.swing.JList smsQueueList;
    private javax.swing.JButton smsUpButton;
    // End of variables declaration//GEN-END:variables
    
}
