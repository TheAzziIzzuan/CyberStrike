document.getElementById("scanButton").addEventListener("click", async () => {
    // Get the current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url); // Extract the URL of the active tab
  
    console.log("Scanning website:", url.hostname); // Log for debugging
  
    // Fetch server info using ip-api
    const response = await fetch(`http://ip-api.com/json/${url.hostname}`);
    const data = await response.json();
  
    console.log("API Response:", data); // Log the API response for debugging
  
    // Display the server information
    const outputDiv = document.getElementById("output");
    if (data.status === "success") {
      outputDiv.innerHTML = `
        <p><strong>IP:</strong> ${data.query}</p>
        <p><strong>City:</strong> ${data.city || "Not available"}</p>
        <p><strong>Region:</strong> ${data.regionName || "Not available"}</p>
        <p><strong>Country:</strong> ${data.country || "Not available"}</p>
        <p><strong>ISP:</strong> ${data.isp || "Not available"}</p>
      `;
    } else {
      outputDiv.innerHTML = `<p>Failed to fetch server information.</p>`;
    }
  });
  