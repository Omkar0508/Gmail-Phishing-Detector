chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension Installed");
  });
  
  async function getAuthToken() {
    return new Promise((resolve, reject) => {
      chrome.identity.getAuthToken({ interactive: true }, (token) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(token);
        }
      });
    });
  }
  
  async function fetchEmails() {
    try {
      const token = await getAuthToken();
      const response = await fetch(
        "https://www.googleapis.com/gmail/v1/users/me/messages?q=after:today",
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
  
      const data = await response.json();
      return data.messages || [];
    } catch (error) {
      console.error("Error fetching emails:", error);
    }
  }
  
  chrome.action.onClicked.addListener(async () => {
    const emails = await fetchEmails();
    chrome.storage.local.set({ emails });
  });
  