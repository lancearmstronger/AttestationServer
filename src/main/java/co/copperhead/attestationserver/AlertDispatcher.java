package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import com.google.common.io.BaseEncoding;

class AlertDispatcher implements Runnable {
    private static final long WAIT_MS = 30 * 1000;
    private static final long DEFAULT_ALERT_MS = 24 * 60 * 60 * 1000;

    private final SQLiteConnection conn;
    private final SQLiteStatement selectAccounts;
    private final SQLiteStatement selectExpired;

    AlertDispatcher() throws SQLiteException {
        conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            AttestationServer.open(conn, true);
            selectAccounts = conn.prepare("SELECT userId from Accounts");
            selectExpired = conn.prepare("SELECT fingerprint FROM Devices " +
                    "WHERE userId = ? AND verifiedTimeLast < ?");
        } catch (final SQLiteException e) {
            conn.dispose();
            throw e;
        }
    }

    @Override
    public void run() {
        while (true) {
            System.err.println("alert check");

            try {
                selectAccounts.reset();
                while (selectAccounts.step()) {
                    final long userId = selectAccounts.columnLong(0);

                    selectExpired.reset();
                    selectExpired.bind(1, userId);
                    selectExpired.bind(2, System.currentTimeMillis() - DEFAULT_ALERT_MS);
                    while (selectExpired.step()) {
                        final byte[] fingerprint = selectExpired.columnBlob(0);
                        final String encoded = BaseEncoding.base16().encode(fingerprint);
                        System.err.println("alert: " + userId + " " + encoded);
                    }
                }
            } catch (final SQLiteException e) {
                e.printStackTrace();
            }

            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }
        }
    }
}
