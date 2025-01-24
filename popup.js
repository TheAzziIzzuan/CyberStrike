document.getElementById("scanButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
  
    const apiKey = "cf0b9da2dcd44d29b2719647092b0e26"; // Replace with your free API key
    const response = await fetch(`https://api.ipgeolocation.io/ipgeo?apiKey=${apiKey}&domain=${url.hostname}`);
    const data = await response.json();
  
    const outputDiv = document.getElementById("output");
    outputDiv.innerHTML = `
      <p><strong>IP:</strong> ${data.ip}</p>
      <p><strong>City:</strong> ${data.city}</p>
      <p><strong>Region:</strong> ${data.state_prov}</p>
      <p><strong>Country:</strong> ${data.country_name}</p>
      <p><strong>ISP:</strong> ${data.isp}</p>
    `;
  });
  