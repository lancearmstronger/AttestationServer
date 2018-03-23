"use strict";

const devices = document.getElementById("devices");
devices.style.display = "block";

fetch("/devices")
    .then(response => {
        if (!response.ok) {
            Project.reject();
        }
        return response.text();
    }).then(text => {
        devices.innerText = text;
    }).catch(error => devices.innerHTML = "<p>Failed to fetch device data.</p>");
