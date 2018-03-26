"use strict";

const fingerprintSplitInterval = 4;
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
            let fingerprint = "";
            for (let i = 0; i < device.fingerprint.length; i += fingerprintSplitInterval) {
                fingerprint += device.fingerprint.substring(i, Math.min(device.fingerprint.length, i + fingerprintSplitInterval));
                if (i + fingerprintSplitInterval < device.fingerprint.length) {
                    fingerprint += "-";
                }
            }

            const info = document.createElement("p");
            info.innerHTML = `<h2>${fingerprint}</h2>
<h3>Verified device information:</h3>
Device: ${device.name}<br/>
OS: ${device.os}<br/>
OS version: ${formatOsVersion(device.pinnedOsVersion)}<br/>
OS patch level: ${formatOsPatchLevel(device.pinnedOsPatchLevel)}<br/>
<button class="toggle">show advanced information</button><span class="hidden"><br/>
Certificate 0: <button class="toggle">show</button><span class="hidden"><br/>${device.pinnedCertificate0}</span><br/>
Certificate 1: <button class="toggle">show</button><span class="hidden"><br/>${device.pinnedCertificate1}</span><br/>
Certificate 2: <button class="toggle">show</button><span class="hidden"><br/>${device.pinnedCertificate2}</span><br/>
Verified boot key: ${device.verifiedBootKey}
</span>
<h3>Information provided by the verified OS:</h3>
Auditor app version: ${device.pinnedAppVersion - attestationAppVersionCodeOffset}
<h3>Attestation history</h3>
First verified time: ${new Date(device.verifiedTimeFirst)}<br/>
Last verified time: ${new Date(device.verifiedTimeLast)}<br/>`
            devices.append(info);

            for (const attestation of device.attestations) {
                const time = document.createElement("h4");
                time.innerText = new Date(attestation.time);
                devices.append(time);

                const p = document.createElement("p");
                if (attestation.strong) {
                    p.innerHTML = "<strong>Successfully performed strong paired verification and identity confirmation.</strong>";
                } else {
                    p.innerHTML = "<strong>Successfully performed basic initial verification and pairing.</strong>";
                }
                devices.append(p);

                const teeEnforcedIntro = document.createElement("p");
                teeEnforcedIntro.innerHTML = "<h5>Verified device information (constants omitted):</h5>";
                devices.append(teeEnforcedIntro);

                const teeEnforced = document.createElement("p");
                teeEnforced.innerText = attestation.teeEnforced;
                devices.append(teeEnforced);

                const osEnforcedIntro = document.createElement("p");
                osEnforcedIntro.innerHTML = "<h5>Information provided by the verified OS:</h5>";
                devices.append(osEnforcedIntro);

                const osEnforced = document.createElement("p");
                osEnforced.innerText = attestation.osEnforced;
                devices.append(osEnforced);
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
