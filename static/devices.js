"use strict";

const devices = document.getElementById("devices");

fetch("/devices")
    .then(response => {
        if (!response.ok) {
            throw new Error(response.statusText);
        }
        return response.text();
    }).then(text => {
        devices.innerText = text;
    }).catch(error => console.log("fetch error: " + error));
