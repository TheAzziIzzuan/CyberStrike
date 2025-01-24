// Event listener for the "Scan Website" button
document.getElementById("scanButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
  
    console.log("Scanning website:", url.hostname);
  
    const loadingSpinner = document.getElementById("loading");
    const outputDiv = document.getElementById("output");
  
    // Show loading spinner
    loadingSpinner.style.display = "block";
    outputDiv.innerHTML = ""; // Clear previous output
  
    try {
      const response = await fetch(`http://ip-api.com/json/${url.hostname}`);
      const data = await response.json();
  
      console.log("API Response:", data);
  
      // Hide spinner
      loadingSpinner.style.display = "none";
  
      if (data.status === "success") {
        outputDiv.style.borderColor = "green";
        outputDiv.innerHTML = `
          <p><strong>🌐 IP:</strong> ${data.query}</p>
          <p><strong>🏙️ City:</strong> ${data.city || "Not available"}</p>
          <p><strong>🗺️ Region:</strong> ${data.regionName || "Not available"}</p>
          <p><strong>🇺🇸 Country:</strong> ${data.country || "Not available"}</p>
          <p><strong>💻 ISP:</strong> ${data.isp || "Not available"}</p>
        `;
      } else {
        outputDiv.style.borderColor = "red";
        outputDiv.innerHTML = `<p>❌ Failed to fetch server information.</p>`;
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      loadingSpinner.style.display = "none"; // Hide spinner
      outputDiv.style.borderColor = "red";
      outputDiv.innerHTML = `<p>❌ Error occurred while fetching data.</p>`;
    }
  });
  
  // Event listener for the "Help" button
  document.getElementById("helpButton").addEventListener("click", () => {
    chrome.tabs.create({ url: "https://www.example.com/help" }); // Replace with your desired URL
  });
  