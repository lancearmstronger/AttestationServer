"use strict";

const attestationAppVersionCodeOffset = 9;
const devices = document.getElementById("devices");
devices.style.display = "block";

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

fetch("/devices.json")
    .then(response => {
        if (!response.ok) {
            Project.reject();
        }
        return response.json();
    }).then(devicesJson => {
        devices.innerText = null;
        for (const device of devicesJson) {
            const h2 = document.createElement("h2");
            h2.innerText = "Device";
            devices.append(h2);

            const pinning = document.createElement("p");
            pinning.innerHTML = `Fingerprint: ${device.fingerprint}<br/>
Pinned certificate 0: <button class="toggle">show</button><span class="cert"><br/>${device.pinnedCertificate0}</span><br/>
Pinned certificate 1: <button class="toggle">show</button><span class="cert"><br/>${device.pinnedCertificate1}</span><br/>
Pinned certificate 2: <button class="toggle">show</button><span class="cert"><br/>${device.pinnedCertificate2}</span><br/>
Pinned verified boot key: ${device.verifiedBootKey}<br/>
Device: ${device.name}<br/>
OS: ${device.os}<br/>
Pinned OS version: ${formatOsVersion(device.pinnedOsVersion)}<br/>
Pinned OS patch level: ${formatOsPatchLevel(device.pinnedOsPatchLevel)}<br/>
Pinned Auditor app version: ${device.pinnedAppVersion - attestationAppVersionCodeOffset}<br/>
First verified time: ${new Date(device.verifiedTimeFirst)}<br/>
Last verified time: ${new Date(device.verifiedTimeLast)}`
            devices.append(pinning);

            const h3 = document.createElement("h3");
            h3.innerText = "Attestation history";
            devices.append(h3);

            for (const attestation of device.attestations) {
                const p = document.createElement("p");
                if (attestation.strong) {
                    p.innerHTML = "<strong>Successfully performed strong paired verification and identity confirmation.</strong>";
                } else {
                    p.innerHTML = "<strong>Successfully performed basic initial verification and pairing.</strong>";
                }
                devices.append(p);

                const teeEnforcedIntro = document.createElement("p");
                teeEnforcedIntro.innerHTML = "<h4>Verified device information:</h4>";
                devices.append(teeEnforcedIntro);

                const teeEnforced = document.createElement("p");
                teeEnforced.innerText = attestation.teeEnforced;
                devices.append(teeEnforced);

                const osEnforcedIntro = document.createElement("p");
                osEnforcedIntro.innerHTML = "<h4>Information provided by the verified OS:</h4>";
                devices.append(osEnforcedIntro);

                const osEnforced = document.createElement("p");
                osEnforced.innerText = attestation.osEnforced;
                devices.append(osEnforced);
            }
        }

        for (const cert of document.getElementsByClassName("toggle")) {
            cert.onclick = event => {
                const target = event.target;
                const cert = target.nextSibling;
                if (cert.style.display === "inline") {
                    target.innerText = "show";
                    cert.style.display = "none";
                } else {
                    target.innerText = "hide";
                    cert.style.display = "inline";
                }
            }
        }
    }).catch(error => {
        console.log(error);
        devices.innerHTML = "<p>Failed to fetch device data.</p>"
    });
