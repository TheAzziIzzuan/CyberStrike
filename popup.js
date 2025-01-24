document.getElementById("scanButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
  
    const apiKey = "7fd4f3f9d3dd4e1e8bff6c78661295fe"; // Replace with your free API key
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
  