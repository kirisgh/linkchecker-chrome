const express = require("express");
const cors = require("cors");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const tls = require("tls");
const https = require("https");
const puppeteer = require("puppeteer");
require("dotenv").config();

const app = express();
const PORT = 3000;
const GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyBkg5kLoZKK7_bZO - bvzjb8jUWkj_58XWA";

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("🚀 Server is running successfully!");
});

function startServer(port) {
    const server = app.listen(port, () => {
        console.log(`✅ Server running on port ${server.address().port}`);
    }).on("error", (err) => {
        if (err.code === "EADDRINUSE") {
            console.warn(`⚠️ Port ${port} in use. Trying a different port...`);
            startServer(0);
        } else {
            console.error(`❌ Server error: ${err.message}`);
        }
    });
}

startServer(PORT);

app.get("/check-link", async (req, res) => {
    const { url } = req.query;
    if (!url) {
        return res.json({ status: "error", warnings: [{ reason: "Invalid URL provided." }] });
    }

    const warnings = [];
    const sslWarning = await checkSSL(url);
    if (sslWarning) warnings.push({ reason: sslWarning });

    const httpWarning = await checkHttpStatus(url);
    if (httpWarning) warnings.push({ reason: httpWarning});

    const malwareWarning = await checkForMalware(url);
    if (malwareWarning) warnings.push({ reason: malwareWarning});

    res.json({ status: warnings.length > 0 ? "warning" : "working", warnings });
});


async function checkSSL(url) {
    return new Promise((resolve) => {
        try {
            const { hostname } = new URL(url);
            const options = { host: hostname, port: 443, rejectUnauthorized: false };

            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate();

                if (!cert || Object.keys(cert).length === 0) {
                    resolve("No valid SSL certificate.");
                } else if (cert.valid_to && new Date(cert.valid_to) < new Date()) {
                    resolve("Expired SSL certificate.");
                } else if (!cert.issuer || !cert.issuer.O) {
                    resolve("Self-signed SSL certificate.");
                } else {
                    resolve(null); // SSL is valid
                }

                socket.end();
            });

            socket.on("error", () => resolve("Fake or misconfigured SSL certificate."));
        } catch (error) {
            resolve("SSL check failed.");
        }
    });
}


async function checkForMalware(url) {
    const apiURL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
    const body = {
        client: { clientId: "link-checker", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
        },
    };
    try {
        const response = await fetch(apiURL, { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
        const data = await response.json();
        return data.matches && data.matches.length > 0 ? data.matches[0].threatType : null;
    } catch (error) {
        return null;
    }
}

async function checkHttpStatus(url) {
    try {
        const response = await fetch(url, { method: "HEAD" });
        return !response.ok ? `HTTP error: ${response.status}` : null;
    } catch (error) {
        return "Site is unreachable";
    }
}

