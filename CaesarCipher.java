import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CaesarCipherGUI {
    private String lastEncryptedText = "";

    public CaesarCipherGUI() {
        JFrame frame = new JFrame("Caesar Cipher GUI");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(4, 2));

        JLabel textLabel = new JLabel("Enter text:");
        JTextField textField = new JTextField(20);
        JLabel shiftLabel = new JLabel("Enter shift (number):");
        JTextField shiftField = new JTextField(20);

        JLabel resultLabel = new JLabel("Result: ");

        JButton encryptButton = new JButton("Encrypt Text");
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String text = textField.getText();
                int shift = Integer.parseInt(shiftField.getText());
                String encryptedText = encrypt(text, shift);
                resultLabel.setText("Encrypted Text: " + encryptedText);
            }
        });

        JButton decryptButton = new JButton("Decrypt Text");
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int shift = Integer.parseInt(shiftField.getText());
                String decryptedText = decrypt(lastEncryptedText, shift);
                resultLabel.setText("Decrypted Text: " + decryptedText);
            }
        });

        panel.add(textLabel);
        panel.add(textField);
        panel.add(shiftLabel);
        panel.add(shiftField);
        panel.add(encryptButton);
        panel.add(decryptButton);
        panel.add(resultLabel);

        frame.getContentPane().add(panel);
        frame.setVisible(true);
    }

    private String encrypt(String text, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append((char) ((c - 'A' + shift) % 26 + 'A'));
            } else if (Character.isLowerCase(c)) {
                result.append((char) ((c - 'a' + shift) % 26 + 'a'));
            } else {
                result.append(c);
            }
        }
        lastEncryptedText = result.toString();
        return result.toString();
    }

    private String decrypt(String text, int shift) {
        return encrypt(text, -shift);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new CaesarCipherGUI();
            }
        });
    }
}
