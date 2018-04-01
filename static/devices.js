"use strict";

const attestationRoot = `-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy
ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD
VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk
Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD
ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB
Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m
qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY
DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm
QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u
JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD
CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy
ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD
qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic
MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1
wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk
-----END CERTIFICATE-----`;
const fingerprintSplitInterval = 4;
const attestationAppVersionCodeOffset = 9;
const create = document.getElementById("create");
const createForm = document.getElementById("create_form");
const createUsername = document.getElementById("create_username");
const createPassword = document.getElementById("create_password");
const createPasswordConfirm = document.getElementById("create_password_confirm");
const login = document.getElementById("login");
const loginForm = document.getElementById("login_form");
const loginUsername = document.getElementById("login_username");
const loginPassword = document.getElementById("login_password");
const loginStatus = document.getElementById("login_status");
const devices = document.getElementById("devices");
const qr = document.getElementById("qr");
devices.style.display = "block";

create.onclick = function() {
    createForm.style.display = "block";
    loginForm.style.display = "none";
}

createPasswordConfirm.oninput = function() {
    if (createPassword.value === createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("");
    }
}

createForm.onsubmit = function(event) {
    event.preventDefault();
    const password = createPassword.value;
    if (password !== createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("Password does not match");
        createPasswordConfirm.reportValidity();
        return;
    }
    const createJson = JSON.stringify({username: createUsername.value, password: password});
    fetch("/create_account", {method: "POST", body: createJson}).then(response => {
        if (!response.ok) {
            Project.reject();
        }
        createForm.style.display = "none";
    }).catch(error => {
        console.log(error);
    });
}

login.onclick = function() {
    loginForm.style.display = "block";
    createForm.style.display = "none";
}

loginForm.onsubmit = function() {
    event.preventDefault();
    const loginJson = JSON.stringify({username: loginUsername.value, password: loginPassword.value});
    fetch("/login", {method: "POST", body: loginJson, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            Project.reject();
        }
        return response.text();
    }).then(requestToken => {
        localStorage.setItem("requestToken", requestToken);
    }).catch(error => {
        console.log(error);
    });
}

const deviceAdminStrings = {
    0: "no",
    1: "yes, with non-system apps",
    2: "yes, but only system apps"
};

function formatOsVersion(osVersion) {
    const padded = ("000000" + osVersion).slice(-6);
    return parseInt(padded.substring(0, 2)) + "." +
        parseInt(padded.substring(2, 4)) + "." +
        parseInt(padded.substring(4, 6));
}

function formatOsPatchLevel(osPatchLevel) {
    const string = osPatchLevel.toString();
    return string.substring(0, 4) + "-" + string.substring(4, 6);
}

function toYesNoString(value) {
    if (value === undefined) {
        return "undefined";
    }
    return value ? "yes" : "no";
}

function demo() {
    qr.src = "/account.png";
    fetchDevices(true);
    login.style.display = "inline";
}

function fetchDevices(demo) {
    let request;
    if (demo) {
        request = fetch("/devices.json");
    } else {
        request = fetch("/devices.json", {method: "POST", body: token, credentials: "same-origin"});
    }
    request.then(response => {
        if (!response.ok) {
            Project.reject();
        }
        return response.json();
    }).then(devicesJson => {
        devices.innerText = null;
        for (const device of devicesJson) {
            let fingerprint = "";
            for (let i = 0; i < device.fingerprint.length; i += fingerprintSplitInterval) {
                fingerprint += device.fingerprint.substring(i, Math.min(device.fingerprint.length, i + fingerprintSplitInterval));
                if (i + fingerprintSplitInterval < device.fingerprint.length) {
                    fingerprint += "-";
                }
            }

            const info = document.createElement("p");
            info.innerHTML = `<h2 class="fingerprint">${fingerprint}</h2>
    <h3>Verified device information:</h3>
    Device: ${device.name}<br/>
    OS: ${device.os}<br/>
    OS version: ${formatOsVersion(device.pinnedOsVersion)}<br/>
    OS patch level: ${formatOsPatchLevel(device.pinnedOsPatchLevel)}<br/>
    <button class="toggle">show advanced information</button><span class="hidden"><br/>
    Certificate 0 (persistent Auditor key): <button class="toggle">show</button><pre class="hidden"><br/>${device.pinnedCertificate0}</pre><br/>
    Certificate 1 (batch): <button class="toggle">show</button><pre class="hidden"><br/>${device.pinnedCertificate1}</pre><br/>
    Certificate 2 (intermediate): <button class="toggle">show</button><pre class="hidden"><br/>${device.pinnedCertificate2}</pre><br/>
    Certificate 3 (root): <button class="toggle">show</button><pre class="hidden"><br/>${attestationRoot}</pre><br/>
    Verified boot key fingerprint: <span class="fingerprint">${device.verifiedBootKey}</span>
    </span>
    <h3>Information provided by the verified OS:</h3>
    Auditor app version: ${device.pinnedAppVersion - attestationAppVersionCodeOffset}<br/>
    User profile secure: ${toYesNoString(device.userProfileSecure)}<br/>
    Enrolled fingerprints: ${toYesNoString(device.enrolledFingerprints)}<br/>
    Accessibility service(s) enabled: ${toYesNoString(device.accessibility)}<br/>
    Device administrator(s) enabled: ${deviceAdminStrings[device.deviceAdmin]}<br/>
    Android Debug Bridge enabled: ${toYesNoString(device.adbEnabled)}<br/>
    Add users from lock screen: ${toYesNoString(device.addUsersWhenLocked)}<br/>
    Disallow new USB peripherals when locked: ${toYesNoString(device.denyNewUsb)}
    <h3>Attestation history</h3>
    First verified time: ${new Date(device.verifiedTimeFirst)}<br/>
    Last verified time: ${new Date(device.verifiedTimeLast)}<br/>
    <button class="toggle">show detailed history</button><div id="history-${device.fingerprint}" class="hidden"></div>`
            devices.append(info);

            const history = document.getElementById("history-" + device.fingerprint);
            for (const attestation of device.attestations) {
                const time = document.createElement("h4");
                time.innerText = new Date(attestation.time);
                history.append(time);

                const p = document.createElement("p");
                if (attestation.strong) {
                    p.innerHTML = "<strong>Successfully performed strong paired verification and identity confirmation.</strong>";
                } else {
                    p.innerHTML = "<strong>Successfully performed basic initial verification and pairing.</strong>";
                }
                history.append(p);

                const teeEnforcedIntro = document.createElement("p");
                teeEnforcedIntro.innerHTML = "<h5>Verified device information (constants omitted):</h5>";
                history.append(teeEnforcedIntro);

                const teeEnforced = document.createElement("p");
                teeEnforced.innerText = attestation.teeEnforced;
                history.append(teeEnforced);

                const osEnforcedIntro = document.createElement("p");
                osEnforcedIntro.innerHTML = "<h5>Information provided by the verified OS:</h5>";
                history.append(osEnforcedIntro);

                const osEnforced = document.createElement("p");
                osEnforced.innerText = attestation.osEnforced;
                history.append(osEnforced);
            }
        }

        for (const toggle of document.getElementsByClassName("toggle")) {
            toggle.onclick = event => {
                const target = event.target;
                const cert = target.nextSibling;
                if (cert.style.display === "inline") {
                    target.innerText = target.innerText.replace("hide", "show");
                    cert.style.display = "none";
                } else {
                    target.innerText = target.innerText.replace("show", "hide");
                    cert.style.display = "inline";
                }
            }
        }
    }).catch(error => {
        console.log(error);
        devices.innerHTML = "<p>Failed to fetch device data.</p>"
    });
}

const token = localStorage.getItem("requestToken");
if (token === null) {
    demo();
} else {
    fetch("/username", {method: "POST", body: token, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            Project.reject();
        }
        return response.text();
    }).then(username => {
        loginForm.style.display = "none";
        loginStatus.innerHTML = `Logged in as <strong>${username}</strong>.`
        fetch("/account.png", {method: "POST", body: token, credentials: "same-origin"}).then(response => {
            if (!response.ok) {
                Project.reject();
            }
            return response.blob();
        }).then(imageBlob => {
            qr.src = URL.createObjectURL(imageBlob);
        }).catch(error => {
            console.log(error);
        });
        fetchDevices(false);
    }).catch(error => {
        console.log(error);
        demo();
    });
}
