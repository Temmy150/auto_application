// When the user clicks the extension icon...
chrome.action.onClicked.addListener(async (tab) => {
    try {
      // Get the active tab's URL
      let queryOptions = { active: true, currentWindow: true };
      let [activeTab] = await chrome.tabs.query(queryOptions);
      const jobUrl = activeTab.url;
     
      // Encode the URL so it can be safely included in a query string
      const encodedUrl = encodeURIComponent(jobUrl);
     
      // Build the destination URL for your web app.
      // For example, if your app is hosted at https://sendmyapps.onrender.com,
      // and your form page accepts a query parameter 'job_url', you can do:
      const destinationUrl = `https://sendmyapps.onrender.com/form?job_url=${encodedUrl}`;
     
      // Open a new tab with the destination URL
      chrome.tabs.create({ url: destinationUrl });
    } catch (error) {
      console.error("Error launching job app:", error);
    }
  });