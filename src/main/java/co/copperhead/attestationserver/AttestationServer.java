package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import com.google.common.primitives.Bytes;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.DataFormatException;

import javax.json.JsonObjectBuilder;
import javax.json.JsonArrayBuilder;
import javax.json.Json;

import attestationserver.AttestationProtocol.DeviceInfo;

import static attestationserver.AttestationProtocol.fingerprintsCopperheadOS;
import static attestationserver.AttestationProtocol.fingerprintsStock;

public class AttestationServer {
    private static final Path CHALLENGE_INDEX_PATH = Paths.get("challenge_index.bin");
    private static final File SAMPLES_DATABASE = new File("samples.db");
    private static final int VERIFY_INTERVAL = 3600;
    static final int BUSY_TIMEOUT = 10 * 1000;
    private static final int QR_CODE_SIZE = 300;
    private static final String DEMO_ACCOUNT = "0000000000000000000000000000000000000000000000000000000000000000";

    private static final Cache<ByteBuffer, Boolean> pendingChallenges = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();
    private static byte[] challengeIndex;

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection samplesConn = new SQLiteConnection(SAMPLES_DATABASE);
        try {
            samplesConn.open();
            samplesConn.exec("PRAGMA journal_mode=WAL");
            samplesConn.exec("CREATE TABLE IF NOT EXISTS Samples (sample TEXT NOT NULL)");
        } finally {
            samplesConn.dispose();
        }

        final SQLiteConnection attestationConn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            attestationConn.open();
            attestationConn.exec("PRAGMA journal_mode=WAL");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Devices (\n" +
                    "fingerprint BLOB PRIMARY KEY NOT NULL,\n" +
                    "pinned_certificate_0 BLOB NOT NULL,\n" +
                    "pinned_certificate_1 BLOB NOT NULL,\n" +
                    "pinned_certificate_2 BLOB NOT NULL,\n" +
                    "pinned_verified_boot_key BLOB NOT NULL,\n" +
                    "pinned_os_version INTEGER NOT NULL,\n" +
                    "pinned_os_patch_level INTEGER NOT NULL,\n" +
                    "pinned_app_version INTEGER NOT NULL,\n" +
                    "user_profile_secure INTEGER NOT NULL,\n" +
                    "enrolled_fingerprints INTEGER NOT NULL,\n" +
                    "accessibility INTEGER NOT NULL,\n" +
                    "device_admin INTEGER NOT NULL,\n" +
                    "adb_enabled INTEGER NOT NULL,\n" +
                    "add_users_when_locked INTEGER NOT NULL,\n" +
                    "deny_new_usb INTEGER NOT NULL,\n" +
                    "verified_time_first INTEGER NOT NULL,\n" +
                    "verified_time_last INTEGER NOT NULL\n" +
                    ")");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Attestations (\n" +
                    "fingerprint BLOB NOT NULL,\n" +
                    "time BLOB NOT NULL,\n" +
                    "strong INTEGER NOT NULL,\n" +
                    "teeEnforced TEXT NOT NULL,\n" +
                    "osEnforced TEXT NOT NULL\n" +
                    ")");
        } finally {
            attestationConn.dispose();
        }

        try {
            challengeIndex = Files.readAllBytes(CHALLENGE_INDEX_PATH);
            if (challengeIndex.length != AttestationProtocol.CHALLENGE_LENGTH) {
                throw new RuntimeException("challenge index is not " + AttestationProtocol.CHALLENGE_LENGTH + " bytes");
            }
        } catch (final IOException e) {
            challengeIndex = AttestationProtocol.getChallenge();
            Files.write(CHALLENGE_INDEX_PATH, challengeIndex);
        }

        final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
        server.createContext("/account.png", new AccountQrHandler());
        server.createContext("/submit", new SubmitHandler());
        server.createContext("/verify", new VerifyHandler());
        server.createContext("/devices.json", new DevicesHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    private static class SubmitHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final InputStream input = exchange.getRequestBody();

                final ByteArrayOutputStream sample = new ByteArrayOutputStream();
                final byte[] buffer = new byte[4096];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    sample.write(buffer, 0, read);

                    if (sample.size() > 64 * 1024) {
                        final String response = "Sample too large\n";
                        exchange.sendResponseHeaders(400, response.length());
                        final OutputStream output = exchange.getResponseBody();
                        output.write(response.getBytes());
                        output.close();
                        return;
                    }
                }

                final SQLiteConnection conn = new SQLiteConnection(SAMPLES_DATABASE);
                try {
                    conn.open();
                    conn.setBusyTimeout(BUSY_TIMEOUT);
                    final SQLiteStatement st = conn.prepare("INSERT INTO Samples VALUES (?)");
                    st.bind(1, sample.toByteArray());
                    st.step();
                    st.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    final String response = "Failed to save data.\n";
                    exchange.sendResponseHeaders(500, response.length());
                    final OutputStream output = exchange.getResponseBody();
                    output.write(response.getBytes());
                    output.close();
                    return;
                } finally {
                    conn.dispose();
                }

                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            final String method = exchange.getRequestMethod();

            if (method.equalsIgnoreCase("GET")) {
                final byte[] challenge = AttestationProtocol.getChallenge();
                pendingChallenges.put(ByteBuffer.wrap(challenge), true);

                final byte[] challengeMessage =
                        Bytes.concat(new byte[]{AttestationProtocol.PROTOCOL_VERSION},
                                challengeIndex, challenge);

                exchange.sendResponseHeaders(200, challengeMessage.length);
                final OutputStream output = exchange.getResponseBody();
                output.write(challengeMessage);
                output.close();
            } else if (method.equalsIgnoreCase("POST")) {
                final String account = Paths.get(exchange.getRequestURI().getPath()).getFileName().toString();
                if (!DEMO_ACCOUNT.equals(account)) {
                    final String response = "invalid account";
                    exchange.sendResponseHeaders(403, response.length());
                    final OutputStream output = exchange.getResponseBody();
                    output.write(response.getBytes());
                    output.close();
                    return;
                }

                final InputStream input = exchange.getRequestBody();

                final ByteArrayOutputStream attestation = new ByteArrayOutputStream();
                final byte[] buffer = new byte[4096];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    attestation.write(buffer, 0, read);

                    if (attestation.size() > AttestationProtocol.MAX_MESSAGE_SIZE) {
                        final String response = "Attestation too large";
                        exchange.sendResponseHeaders(400, response.length());
                        final OutputStream output = exchange.getResponseBody();
                        output.write(response.getBytes());
                        output.close();
                        return;
                    }
                }

                final byte[] attestationResult = attestation.toByteArray();

                try {
                    AttestationProtocol.verifySerialized(attestationResult, pendingChallenges);
                } catch (final BufferUnderflowException | DataFormatException | GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    final String response = "Error\n";
                    exchange.sendResponseHeaders(400, response.length());
                    final OutputStream output = exchange.getResponseBody();
                    output.write(response.getBytes());
                    output.close();
                    return;
                }

                final String response = Integer.toString(VERIFY_INTERVAL);
                exchange.sendResponseHeaders(200, response.length());
                final OutputStream output = exchange.getResponseBody();
                output.write(response.getBytes());
                output.close();
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static void createQrCode(final byte[] contents, final OutputStream output) throws IOException {
        final BitMatrix result;
        try {
            final QRCodeWriter writer = new QRCodeWriter();
            final Map<EncodeHintType,Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, "ISO-8859-1");
            try {
                result = writer.encode(new String(contents, "ISO-8859-1"), BarcodeFormat.QR_CODE,
                        QR_CODE_SIZE, QR_CODE_SIZE, hints);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("ISO-8859-1 not supported", e);
            }
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }

        MatrixToImageWriter.writeToStream(result, "png", output);
    }

    private static class AccountQrHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.getResponseHeaders().set("Cache-Control", "private, max-age=1800");
                exchange.sendResponseHeaders(200, 0);
                final OutputStream output = exchange.getResponseBody();
                final String contents = "attestation.copperhead.co " + DEMO_ACCOUNT + " " + VERIFY_INTERVAL;
                createQrCode(contents.getBytes(), output);
                output.close();
            } else {
                exchange.getResponseHeaders().set("Allow", "GET");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static String convertToPem(final byte[] derEncoded) {
        return "-----BEGIN CERTIFICATE-----\n" +
                new String(Base64.getMimeEncoder(64, "\n".getBytes()).encode(derEncoded)) +
                "\n-----END CERTIFICATE-----";
    }

    private static class DevicesHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.sendResponseHeaders(200, 0);
                final OutputStream output = exchange.getResponseBody();
                final String response = "Devices\n";

                final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                final JsonArrayBuilder devices = Json.createArrayBuilder();
                try {
                    conn.openReadonly();
                    conn.setBusyTimeout(BUSY_TIMEOUT);

                    final JsonObjectBuilder device = Json.createObjectBuilder();
                    final SQLiteStatement select = conn.prepare("SELECT hex(fingerprint), pinned_certificate_0, pinned_certificate_1, pinned_certificate_2, hex(pinned_verified_boot_key), pinned_os_version, pinned_os_patch_level, pinned_app_version, user_profile_secure, enrolled_fingerprints, accessibility, device_admin, adb_enabled, add_users_when_locked, deny_new_usb, verified_time_first, verified_time_last FROM Devices ORDER BY verified_time_first");
                    while (select.step()) {
                        device.add("fingerprint", select.columnString(0));
                        device.add("pinnedCertificate0", convertToPem(select.columnBlob(1)));
                        device.add("pinnedCertificate1", convertToPem(select.columnBlob(2)));
                        device.add("pinnedCertificate2", convertToPem(select.columnBlob(3)));
                        final String verifiedBootKey = select.columnString(4);
                        device.add("verifiedBootKey", verifiedBootKey);
                        DeviceInfo info = fingerprintsCopperheadOS.get(verifiedBootKey);
                        if (info != null) {
                            device.add("os", "CopperheadOS");
                        } else {
                            device.add("os", "Stock");
                            info = fingerprintsStock.get(verifiedBootKey);
                            if (info == null) {
                                throw new RuntimeException("invalid fingerprint");
                            }
                        }
                        device.add("name", info.name);
                        device.add("pinnedOsVersion", select.columnInt(5));
                        device.add("pinnedOsPatchLevel", select.columnInt(6));
                        device.add("pinnedAppVersion", select.columnInt(7));
                        device.add("userProfileSecure", select.columnInt(8));
                        device.add("enrolledFingerprints", select.columnInt(9));
                        device.add("accessibility", select.columnInt(10));
                        device.add("deviceAdmin", select.columnInt(11));
                        device.add("adbEnabled", select.columnInt(12));
                        device.add("addUsersWhenLocked", select.columnInt(13));
                        device.add("denyNewUsb", select.columnInt(14));
                        device.add("verifiedTimeFirst", select.columnLong(15));
                        device.add("verifiedTimeLast", select.columnLong(16));

                        final SQLiteStatement history = conn.prepare("SELECT time, strong, teeEnforced, osEnforced FROM Attestations WHERE hex(fingerprint) = ? ORDER BY time");
                        history.bind(1, select.columnString(0));

                        final JsonArrayBuilder attestations = Json.createArrayBuilder();
                        while (history.step()) {
                            attestations.add(Json.createObjectBuilder()
                                    .add("time", history.columnLong(0))
                                    .add("strong", history.columnInt(1) != 0)
                                    .add("teeEnforced", history.columnString(2))
                                    .add("osEnforced", history.columnString(3))
                                    .build());
                        }
                        device.add("attestations", attestations.build());
                        devices.add(device.build());

                        history.dispose();
                    }
                    select.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                    return;
                } finally {
                    conn.dispose();
                }

                output.write(devices.build().toString().getBytes());
                output.close();
            } else {
                exchange.getResponseHeaders().set("Allow", "GET");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
}
