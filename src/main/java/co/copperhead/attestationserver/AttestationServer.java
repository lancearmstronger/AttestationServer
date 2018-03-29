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

import org.bouncycastle.crypto.generators.SCrypt;

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
import java.security.MessageDigest;
import java.security.SecureRandom;
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
    private static final String DEMO_SUBSCRIBE_KEY = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final long SESSION_LENGTH = 1000 * 60 * 60 * 48;

    private static final Cache<ByteBuffer, Boolean> pendingChallenges = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();
    private static byte[] challengeIndex;

    static void open(final SQLiteConnection conn) throws SQLiteException {
        conn.open();
        conn.exec("PRAGMA foreign_keys=ON");
    }

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection samplesConn = new SQLiteConnection(SAMPLES_DATABASE);
        try {
            open(samplesConn);
            samplesConn.exec("PRAGMA journal_mode=WAL");
            samplesConn.exec("CREATE TABLE IF NOT EXISTS Samples (sample TEXT NOT NULL)");
        } finally {
            samplesConn.dispose();
        }

        final SQLiteConnection attestationConn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(attestationConn);
            attestationConn.exec("PRAGMA journal_mode=WAL");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Devices (\n" +
                    "fingerprint BLOB PRIMARY KEY NOT NULL,\n" +
                    "pinnedCertificate0 BLOB NOT NULL,\n" +
                    "pinnedCertificate1 BLOB NOT NULL,\n" +
                    "pinnedCertificate2 BLOB NOT NULL,\n" +
                    "pinnedVerifiedBootKey BLOB NOT NULL,\n" +
                    "pinnedOsVersion INTEGER NOT NULL,\n" +
                    "pinnedOsPatchLevel INTEGER NOT NULL,\n" +
                    "pinnedAppVersion INTEGER NOT NULL,\n" +
                    "userProfileSecure INTEGER NOT NULL CHECK (userProfileSecure in (0, 1)),\n" +
                    "enrolledFingerprints INTEGER NOT NULL CHECK (enrolledFingerprints in (0, 1)),\n" +
                    "accessibility INTEGER NOT NULL CHECK (accessibility in (0, 1)),\n" +
                    "deviceAdmin INTEGER NOT NULL CHECK (deviceAdmin in (0, 1, 2)),\n" +
                    "adbEnabled INTEGER NOT NULL CHECK (adbEnabled in (0, 1)),\n" +
                    "addUsersWhenLocked INTEGER NOT NULL CHECK (addUsersWhenLocked in (0, 1)),\n" +
                    "denyNewUsb INTEGER NOT NULL CHECK (denyNewUsb in (0, 1)),\n" +
                    "verifiedTimeFirst INTEGER NOT NULL,\n" +
                    "verifiedTimeLast INTEGER NOT NULL\n" +
                    ")");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Attestations (\n" +
                    "fingerprint BLOB NOT NULL REFERENCES Devices (fingerprint),\n" +
                    "time BLOB NOT NULL,\n" +
                    "strong INTEGER NOT NULL CHECK (strong in (0, 1)),\n" +
                    "teeEnforced TEXT NOT NULL,\n" +
                    "osEnforced TEXT NOT NULL\n" +
                    ")");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Accounts (\n" +
                    "userId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" +
                    "username TEXT UNIQUE NOT NULL,\n" +
                    "passwordHash BLOB UNIQUE NOT NULL,\n" +
                    "passwordSalt BLOB UNIQUE NOT NULL,\n" +
                    "subscribeKey BLOB UNIQUE NOT NULL,\n" +
                    "creationTime INTEGER NOT NULL\n" +
                    ")");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Sessions (\n" +
                    "userId INTEGER NOT NULL REFERENCES Accounts (userId),\n" +
                    "cookieToken BLOB UNIQUE NOT NULL,\n" +
                    "requestToken BLOB UNIQUE NOT NULL,\n" +
                    "expiryTime INTEGER NOT NULL\n" +
                    ")");
            attestationConn.exec("CREATE INDEX IF NOT EXISTS sessionExpiryTimeIndex " +
                    "ON Sessions (expiryTime)");
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

    private static byte[] hash(final byte[] password, final byte[] salt) {
        return SCrypt.generate(password, salt, 32768, 8, 1, 32);
    }

    private static void createAccount(final String username, final String password) throws SQLiteException {
        final SecureRandom random = new SecureRandom();
        final byte[] passwordSalt = new byte[32];
        random.nextBytes(passwordSalt);
        final byte[] passwordHash = hash(password.getBytes(), passwordSalt);
        final byte[] subscribeKey = new byte[32];
        random.nextBytes(subscribeKey);

        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(conn);
            conn.setBusyTimeout(BUSY_TIMEOUT);
            final SQLiteStatement insert = conn.prepare("INSERT INTO Accounts " +
                    "(username, passwordHash, passwordSalt, subscribeKey, creationTime) " +
                    "VALUES (?, ?, ?, ?, ?)");
            insert.bind(1, username);
            insert.bind(2, passwordHash);
            insert.bind(3, passwordSalt);
            insert.bind(4, subscribeKey);
            insert.bind(5, System.currentTimeMillis());
            insert.step();
            insert.dispose();
        } finally {
            conn.dispose();
        }
    }

    private static class Session {
        final long userId;
        final byte[] cookieToken;
        final byte[] requestToken;
        final long expiryTime;

        Session(final long userId, final byte[] cookieToken, final byte[] requestToken,
                final long expiryTime) {
            this.userId = userId;
            this.cookieToken = cookieToken;
            this.requestToken = requestToken;
            this.expiryTime = expiryTime;
        }
    }

    private static Session login(final String username, final String password) throws GeneralSecurityException, SQLiteException {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(conn);
            conn.setBusyTimeout(BUSY_TIMEOUT);
            final SQLiteStatement select = conn.prepare("SELECT userId, passwordHash, passwordSalt FROM Accounts WHERE username = ?");
            select.bind(1, username);
            select.step();
            final long userId = select.columnLong(0);
            final byte[] passwordHash = select.columnBlob(1);
            final byte[] passwordSalt = select.columnBlob(2);
            select.dispose();
            if (!MessageDigest.isEqual(hash(password.getBytes(), passwordSalt), passwordHash)) {
                throw new GeneralSecurityException("invalid credentials");
            }

            final long now = System.currentTimeMillis();
            final SQLiteStatement delete = conn.prepare("DELETE FROM Sessions where expiryTime < ?");
            delete.bind(1, now);
            delete.step();
            delete.dispose();

            final SecureRandom random = new SecureRandom();
            final byte[] cookieToken = new byte[32];
            random.nextBytes(cookieToken);
            final byte[] requestToken = new byte[32];
            random.nextBytes(requestToken);
            final long expiryTime = now + SESSION_LENGTH;

            final SQLiteStatement insert = conn.prepare("INSERT INTO Sessions " +
                    "(userId, cookieToken, requestToken, expiryTime) VALUES (?, ?, ?, ?)");
            insert.bind(1, userId);
            insert.bind(2, cookieToken);
            insert.bind(3, requestToken);
            insert.bind(4, expiryTime);
            insert.step();
            insert.dispose();

            return new Session(userId, cookieToken, requestToken, expiryTime);
        } finally {
            conn.dispose();
        }
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
                        try (final OutputStream output = exchange.getResponseBody()) {
                            output.write(response.getBytes());
                        }
                        return;
                    }
                }

                final SQLiteConnection conn = new SQLiteConnection(SAMPLES_DATABASE);
                try {
                    open(conn);
                    conn.setBusyTimeout(BUSY_TIMEOUT);
                    final SQLiteStatement insert = conn.prepare("INSERT INTO Samples VALUES (?)");
                    insert.bind(1, sample.toByteArray());
                    insert.step();
                    insert.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    final String response = "Failed to save data.\n";
                    exchange.sendResponseHeaders(500, response.length());
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response.getBytes());
                    }
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
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(challengeMessage);
                }
            } else if (method.equalsIgnoreCase("POST")) {
                final String account = Paths.get(exchange.getRequestURI().getPath()).getFileName().toString();
                if (!DEMO_SUBSCRIBE_KEY.equals(account)) {
                    final String response = "invalid subscribe key";
                    exchange.sendResponseHeaders(403, response.length());
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response.getBytes());
                    }
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
                        try (final OutputStream output = exchange.getResponseBody()) {
                            output.write(response.getBytes());
                        }
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
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response.getBytes());
                    }
                    return;
                }

                final String response = Integer.toString(VERIFY_INTERVAL);
                exchange.sendResponseHeaders(200, response.length());
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(response.getBytes());
                }
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
                try (final OutputStream output = exchange.getResponseBody()) {
                    final String contents = "attestation.copperhead.co " + DEMO_SUBSCRIBE_KEY + " " + VERIFY_INTERVAL;
                    createQrCode(contents.getBytes(), output);
                }
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
                final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                final JsonArrayBuilder devices = Json.createArrayBuilder();
                try {
                    conn.openReadonly();
                    conn.setBusyTimeout(BUSY_TIMEOUT);

                    final JsonObjectBuilder device = Json.createObjectBuilder();
                    final SQLiteStatement select = conn.prepare("SELECT hex(fingerprint), pinnedCertificate0, pinnedCertificate1, pinnedCertificate2, hex(pinnedVerifiedBootKey), pinnedOsVersion, pinnedOsPatchLevel, pinnedAppVersion, userProfileSecure, enrolledFingerprints, accessibility, deviceAdmin, adbEnabled, addUsersWhenLocked, denyNewUsb, verifiedTimeFirst, verifiedTimeLast FROM Devices ORDER BY verifiedTimeFirst");
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

                exchange.sendResponseHeaders(200, 0);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(devices.build().toString().getBytes());
                }
            } else {
                exchange.getResponseHeaders().set("Allow", "GET");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
}
