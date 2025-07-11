import { initializeApp } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js";
import { getDatabase, ref, get } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-database.js";

// Initialize Firebase (replace with your Firebase config)
const firebaseConfig = {
  apiKey: "AIzaSyD00O5_-2rTvf0Scx-oOrqB7glOwSomKBU",
  authDomain: "goldenshield-01.firebaseapp.com",
  databaseURL: "https://goldenshield-01-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "goldenshield-01",
  storageBucket: "goldenshield-01.firebasestorage.app",
  messagingSenderId: "475759246719",
  appId: "1:475759246719:web:544ae71ee593a02316ee4a",
  measurementId: "G-Z1S2GFHDCC"
};

const app = initializeApp(firebaseConfig);
const database = getDatabase(app);

async function loadAndApplyRules() {
    try {
        const response = await fetch("http://localhost:5000/blocked_sites");
        if (!response.ok) {
            throw new Error(`Network response was not ok: ${response.statusText}`);
        }
        const sites = await response.json();

        const rules = [];
        let ruleId = 1;

        for (const site of sites) {
            try {
                const hostname = new URL(site).hostname;

                rules.push({
                    id: ruleId++,
                    priority: 1,
                    action: { type: "block" },
                    condition: {
                        urlFilter: `||${hostname}^`,
                        resourceTypes: ["main_frame"]
                    }
                });
            } catch (err) {
                console.warn(`Invalid URL skipped: ${site}`);
            }
        }

        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: rules.map(rule => rule.id),
            addRules: rules
        }, () => {
            if (chrome.runtime.lastError) {
                console.error("Error updating rules:", chrome.runtime.lastError.message);
            } else {
                console.log("✅ Rules updated:", rules.length);
            }
        });

    } catch (err) {
        console.error("Failed to load blocked sites:", err);
    }
}

chrome.runtime.onInstalled.addListener(() => {
    loadAndApplyRules();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.command === "refresh") {
        loadAndApplyRules();
        sendResponse({ status: "refreshed" });
        return true; // Keeps async callback
    }
});
