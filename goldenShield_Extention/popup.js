document.getElementById("refresh").addEventListener("click", handleRefresh);

async function handleRefresh() {
    chrome.runtime.sendMessage({ command: "refresh" }, async (response) => {
        if (response && response.status === "refreshed") {
            alert("Block list refreshed successfully!");
            await loadBrowsingHistory(); // Load browsing history after refreshing
        }
    });
}

  async function loadBrowsingHistory() {
      try {
          const response = await fetch("http://localhost:5000/user_dashboard");
          console.log("Response status:", response.status); // Log the response status
          if (!response.ok) {
              throw new Error("Network response was not ok");
          }
          const data = await response.json();
          // ... rest of your code
      } catch (error) {
          console.error("Failed to load browsing history:", error);
      }
  }


// Call loadBrowsingHistory on popup open
document.addEventListener("DOMContentLoaded", loadBrowsingHistory);
