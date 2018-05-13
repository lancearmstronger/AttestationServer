package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.util.Properties;

import com.google.common.io.BaseEncoding;

class AlertDispatcher implements Runnable {
    private static final long WAIT_MS = 15 * 60 * 1000;
    private static final int TIMEOUT_MS = 30 * 1000;

    @Override
    public void run() {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        final SQLiteStatement selectConfiguration;
        final SQLiteStatement selectAccounts;
        final SQLiteStatement selectExpired;
        final SQLiteStatement selectEmails;
        try {
            AttestationServer.open(conn, false);
            selectConfiguration = conn.prepare("SELECT " +
                    "(SELECT value FROM Configuration WHERE key = 'emailUsername'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailPassword'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailHost'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailPort')");
            selectAccounts = conn.prepare("SELECT userId, alertDelay FROM Accounts");
            selectExpired = conn.prepare("SELECT fingerprint FROM Devices " +
                    "WHERE userId = ? AND verifiedTimeLast < ? AND deletionTime IS NULL");
            selectEmails = conn.prepare("SELECT address FROM EmailAddresses WHERE userId = ?");
        } catch (final SQLiteException e) {
            conn.dispose();
            throw new RuntimeException(e);
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            System.err.println("dispatching alerts");

            try {
                selectConfiguration.step();
                final String username = selectConfiguration.columnString(0);
                final String password = selectConfiguration.columnString(1);
                final String host = selectConfiguration.columnString(2);
                final String port = selectConfiguration.columnString(3);
                if (username == null || password == null || host == null || port == null) {
                    System.err.println("missing email configuration");
                    continue;
                }

                final Properties props = new Properties();
                props.put("mail.transport.protocol.rfc822", "smtps");
                props.put("mail.smtps.auth", true);
                props.put("mail.smtps.host", host);
                props.put("mail.smtps.port", port);
                props.put("mail.smtps.connectiontimeout", Integer.toString(TIMEOUT_MS));
                props.put("mail.smtps.timeout", Integer.toString(TIMEOUT_MS));
                props.put("mail.smtps.writetimeout", Integer.toString(TIMEOUT_MS));

                final Session session = Session.getInstance(props,
                        new javax.mail.Authenticator() {
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(username, password);
                            }
                        });

                while (selectAccounts.step()) {
                    final long userId = selectAccounts.columnLong(0);
                    final int alertDelay = selectAccounts.columnInt(1);

                    boolean alert = false;
                    final StringBuilder body = new StringBuilder();

                    selectExpired.bind(1, userId);
                    selectExpired.bind(2, System.currentTimeMillis() - alertDelay * 1000);
                    while (selectExpired.step()) {
                        alert = true;

                        final byte[] fingerprint = selectExpired.columnBlob(0);
                        final String encoded = BaseEncoding.base16().encode(fingerprint);
                        body.append("* ").append(encoded).append("\n");
                    }
                    selectExpired.reset();

                    if (alert) {
                        selectEmails.bind(1, userId);
                        while (selectEmails.step()) {
                            final String address = selectEmails.columnString(0);
                            System.err.println("sending email to " + address);
                            try {
                                final Message message = new MimeMessage(session);
                                message.setFrom(new InternetAddress(username));
                                message.setRecipients(Message.RecipientType.TO,
                                        InternetAddress.parse(address));
                                message.setSubject(
                                        "Devices failed to provide valid attestations within " +
                                        alertDelay / 60 / 60 + " hours");
                                message.setText("The following devices have failed to provide valid attestations before the expiry time:\n\n" +
                                        body.toString());

                                Transport.send(message);
                            } catch (final MessagingException e) {
                                e.printStackTrace();
                            }
                        }
                        selectEmails.reset();
                    }
                }
            } catch (final SQLiteException e) {
                e.printStackTrace();
            } finally {
                try {
                    selectConfiguration.reset();
                    selectAccounts.reset();
                    selectExpired.reset();
                    selectEmails.reset();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
