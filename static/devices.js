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
const createForm = document.getElementById("create_form");
const createUsername = document.getElementById("create_username");
const createPassword = document.getElementById("create_password");
const createPasswordConfirm = document.getElementById("create_password_confirm");
const loginForm = document.getElementById("login_form");
const loginUsername = document.getElementById("login_username");
const loginPassword = document.getElementById("login_password");
const loginStatus = document.getElementById("login_status");
const username = document.getElementById("username");
const formToggles = document.getElementById("form_toggles");
const logout = document.getElementById("logout");
const logoutEverywhere = document.getElementById("logout_everywhere");
const accountButtons = document.getElementById("account_buttons");
const changePassword = document.getElementById("change_password");
const changePasswordForm = document.getElementById("change_password_form");
const configuration = document.getElementById("configuration");
const devices = document.getElementById("devices");
const qr = document.getElementById("qr");
const rotate = document.getElementById("rotate");
const accountContent = document.getElementById("account_content");

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
        return "unknown";
    }
    return value ? "yes" : "no";
}

function showLoggedOut() {
    formToggles.style.display = "inline";
}

function reloadQrCode() {
    qr.src = "/placeholder.png";
    qr.alt = "";
    fetch("/account.png", {method: "POST", body: localStorage.getItem("requestToken"), credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            return Promise.reject();
        }
        return response.blob();
    }).then(imageBlob => {
        qr.src = URL.createObjectURL(imageBlob);
        qr.alt = "account QR code";
        rotate.style.display = "block";
    }).catch(error => {
        console.log(error);
    });
}

function displayLogin(account) {
    formToggles.style.display = "none";
    createForm.style.display = "none";
    loginForm.style.display = "none";
    loginForm.submit.disabled = false;
    accountButtons.style.display = "inline";
    loginStatus.style.display = "inline";
    username.innerText = account.username;
    accountContent.style.display = "block";
    configuration.verify_interval.value = account.verifyInterval / 60 / 60;
    configuration.alert_delay.value = account.alertDelay / 60 / 60;
    if (account.email !== undefined) {
        configuration.email.value = account.email;
    }
    reloadQrCode();
    fetchDevices();
}

function create(tagName, text) {
    const element = document.createElement(tagName);
    element.innerText = text;
    return element;
}

function fetchDevices() {
    devices.appendChild(create("p", "Loading device data..."));

    const token = localStorage.getItem("requestToken");
    fetch("/devices.json", {method: "POST", body: token, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            return Promise.reject();
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

            const info = document.createElement("div");
            info.innerHTML = `<h2 class="fingerprint">${fingerprint}</h2>
<button class="delete">delete device</button>
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
Disallow new USB peripherals when locked: ${toYesNoString(device.denyNewUsb)}<br/>
OEM unlocking allowed: ${toYesNoString(device.oemUnlockAllowed)}
<h3>Attestation history</h3>
First verified time: ${new Date(device.verifiedTimeFirst)}<br/>
Last verified time: ${new Date(device.verifiedTimeLast)}<br/>
<button class="toggle">show detailed history</button><div id="history-${device.fingerprint}" class="hidden"></div>`
            devices.appendChild(info);

            const history = document.getElementById("history-" + device.fingerprint);
            for (const attestation of device.attestations) {
                history.appendChild(create("h4", new Date(attestation.time)));

                const p = document.createElement("p");
                const result = attestation.strong ?
                    "Successfully performed strong paired verification and identity confirmation." :
                    "Successfully performed basic initial verification and pairing.";
                p.appendChild(create("strong", result));
                history.appendChild(p);

                history.appendChild(create("h5", "Verified device information (constants omitted):"));
                history.appendChild(create("p", attestation.teeEnforced));
                history.appendChild(create("h5", "Information provided by the verified OS:"));
                history.appendChild(create("p", attestation.osEnforced));
            }

            info.getElementsByClassName("delete")[0].onclick = event => {
                if (confirm("Are you sure you want to delete the device " + fingerprint + "?")) {
                    event.target.disabled = true;

                    const data = JSON.stringify({
                        "requestToken": localStorage.getItem("requestToken"),
                        "fingerprint": device.fingerprint
                    });
                    fetch("/delete_device", {method: "POST", body: data, credentials: "same-origin"}).then(response => {
                        if (response.status === 403) {
                            localStorage.removeItem("requestToken");
                        }
                        if (!response.ok) {
                            return Promise.reject();
                        }
                        event.target.disabled = false;
                        console.log("deleted device " + device.fingerprint);
                        devices.removeChild(info);
                    }).catch(error => {
                        event.target.disabled = false;
                        console.log(error);
                    });
                }
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
        devices.innerText = null;
        devices.appendChild(create("p", "Failed to fetch device data."));
    });
}

const token = localStorage.getItem("requestToken");
if (token === null) {
    showLoggedOut();
} else {
    fetch("/account", {method: "POST", body: token, credentials: "same-origin"}).then(response => {
        if (response.status === 403) {
            localStorage.removeItem("requestToken");
        }
        if (!response.ok) {
            return Promise.reject();
        }
        return response.json();
    }).then(account => {
        displayLogin(account);
    }).catch(error => {
        console.log(error);
        showLoggedOut();
    });
}

document.getElementById("create").onclick = () => {
    formToggles.style.display = "none";
    createForm.style.display = "block";
}

createPasswordConfirm.oninput = () => {
    if (createPassword.value === createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("");
    }
}

changePasswordForm.new_password_confirm.oninput = () => {
    if (changePasswordForm.new_password.value === changePasswordForm.new_password_confirm.value) {
        changePasswordForm.new_password_confirm.setCustomValidity("");
    }
}

function clearAlertDelayValidity() {
    if (parseInt(configuration.alert_delay.value) > parseInt(configuration.verify_interval.value)) {
        configuration.alert_delay.setCustomValidity("");
    }
}

configuration.verify_interval.oninput = clearAlertDelayValidity;
configuration.alert_delay.oninput = clearAlertDelayValidity;

function clearValidity() {
    this.setCustomValidity("");
}

createUsername.oninput = clearValidity;
loginUsername.oninput = clearValidity;
loginPassword.oninput = clearValidity;

function login(username, password) {
    const loginJson = JSON.stringify({username: username, password: password});
    fetch("/login", {method: "POST", body: loginJson, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            if (response.status === 400) {
                loginUsername.setCustomValidity("Username does not exist");
                loginUsername.reportValidity();
            } else if (response.status === 403) {
                loginPassword.setCustomValidity("Incorrect password");
                loginPassword.reportValidity();
            }
            return Promise.reject();
        }
        return response.text();
    }).then(requestToken => {
        localStorage.setItem("requestToken", requestToken);
        fetch("/account", {method: "POST", body: requestToken, credentials: "same-origin"}).then(response => {
            if (!response.ok) {
                return Promise.reject();
            }
            return response.json();
        }).then(account => {
            displayLogin(account);
        }).catch(error => {
            console.log(error);
        });
    }).catch(error => {
        loginForm.submit.disabled = false;
        console.log(error);
    });
}

createForm.onsubmit = event => {
    event.preventDefault();

    const password = createPassword.value;
    if (password !== createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("Password does not match");
        createPasswordConfirm.reportValidity();
        return;
    }
    const username = createUsername.value;
    const createJson = JSON.stringify({username: username, password: password});
    createForm.submit.disabled = true;
    fetch("/create_account", {method: "POST", body: createJson}).then(response => {
        if (!response.ok) {
            if (response.status === 409) {
                createUsername.setCustomValidity("Username is already taken");
                createUsername.reportValidity();
            }
            return Promise.reject();
        }
        createForm.submit.disabled = false;
        createForm.style.display = "none";
        login(username, password);
    }).catch(error => {
        createForm.submit.disabled = false;
        console.log(error);
    });
}

document.getElementById("login").onclick = () => {
    formToggles.style.display = "none";
    loginForm.style.display = "block";
}

loginForm.onsubmit = event => {
    event.preventDefault();

    loginForm.submit.disabled = true;
    login(loginUsername.value, loginPassword.value);
}

for (const cancel of document.getElementsByClassName("cancel")) {
    cancel.onclick = function() {
        this.parentElement.style.display = "none";
        formToggles.style.display = "inline";
    }
}

for (const logoutButton of document.getElementsByClassName("logout")) {
    logoutButton.onclick = () => {
        const requestToken = localStorage.getItem("requestToken");
        logout.disabled = true;
        logoutEverywhere.disabled = true;
        const path = logoutButton === logout ? "/logout" : "/logout_everywhere";
        fetch(path, {method: "POST", body: requestToken, credentials: "same-origin"}).then(response => {
            if (!response.ok) {
                return Promise.reject();
            }

            localStorage.removeItem("requestToken");
            loginStatus.style.display = "none";
            devices.innerText = null;
            accountContent.style.display = "none";
            qr.src = "/placeholder.png";
            qr.alt = "";
            accountButtons.style.display = "none";
            logout.disabled = false;
            logoutEverywhere.disabled = false;
            showLoggedOut();
        }).catch(error => {
            logout.disabled = false;
            logoutEverywhere.disabled = false;
            console.log(error);
        });
    }
}

changePassword.onclick = () => {
    accountButtons.style.display = "none";
    changePasswordForm.style.display = "block";
}

changePasswordForm.onsubmit = event => {
    event.preventDefault();

    const newPassword = changePasswordForm.new_password.value;
    if (newPassword !== changePasswordForm.new_password_confirm.value) {
        changePasswordForm.new_password_confirm.setCustomValidity("Password does not match");
        changePasswordForm.new_password_confirm.reportValidity();
        return;
    }

    changePasswordForm.submit.disabled = true;
    const data = JSON.stringify({
        "requestToken": localStorage.getItem("requestToken"),
        "currentPassword": changePasswordForm.current_password.value,
        "newPassword": newPassword
    });
    fetch("/change_password", {method: "POST", body: data, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            return Promise.reject();
        }
        changePasswordForm.submit.disabled = false;
        accountButtons.style.display = "inline";
        changePasswordForm.style.display = "none";
    }).catch(error => {
        changePasswordForm.submit.disabled = false;
        console.log(error);
    });
}

for (const cancel of document.getElementsByClassName("cancel_account")) {
    cancel.onclick = function() {
        this.parentElement.style.display = "none";
        accountButtons.style.display = "inline";
    }
}

rotate.onclick = event => {
    if (confirm("Are you sure you want to rotate the device subscription key?")) {
        rotate.disabled = true;
        const requestToken = localStorage.getItem("requestToken");
        fetch("/rotate", {method: "POST", body: requestToken, credentials: "same-origin"}).then(response => {
            if (!response.ok) {
                return Promise.reject();
            }
            rotate.disabled = false;
            reloadQrCode();
        }).catch(error => {
            rotate.disabled = false;
            console.log(error);
        });
    }
}

configuration.onsubmit = event => {
    event.preventDefault();

    const verifyInterval = parseInt(configuration.verify_interval.value);
    const alertDelay = parseInt(configuration.alert_delay.value);

    if (alertDelay <= verifyInterval) {
        configuration.alert_delay.setCustomValidity("Alert delay must be larger than verify interval");
        configuration.alert_delay.reportValidity();
        return;
    }

    configuration.submit.disabled = true;
    const data = JSON.stringify({
        "requestToken": localStorage.getItem("requestToken"),
        "verifyInterval": verifyInterval * 60 * 60,
        "alertDelay": alertDelay * 60 * 60,
        "email": configuration.email.value
    });
    fetch("/configuration", {method: "POST", body: data, credentials: "same-origin"}).then(response => {
        if (!response.ok) {
            return Promise.reject();
        }
        configuration.submit.disabled = false;
        reloadQrCode();
    }).catch(error => {
        configuration.submit.disabled = false;
        console.log(error);
    });
}
