chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [1],
    addRules: [
      {
        id: 1,
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: "127.0.0.1|192.168.|10.0.|169.254.|::1",
          resourceTypes: ["xmlhttprequest", "sub_frame", "script", "ping"]
        }
      }
    ]
  });
  