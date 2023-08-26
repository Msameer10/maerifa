const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');

// Function to fetch article data from data.json
async function fetchArticleData() {
  try {
    const response = await fetch('../data.json'); // Assuming data.json is in the main directory
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching article data:', error);
    return [];
  }
}

// Function to display search results as a dropdown
function displaySearchResults(results) {
  searchResultsContainer.innerHTML = ''; // Clear existing results

  results.forEach(article => {
    const resultItem = document.createElement('div');
    resultItem.className = 'search-result';
    resultItem.textContent = article.title;
    
    resultItem.addEventListener('click', () => {
      window.location.href = article.url; // Navigate to the selected article
    });

    searchResultsContainer.appendChild(resultItem);
  });
}

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  fetchArticleData().then(articles => {
    const searchResults = articles.filter(article =>
      article.title.toLowerCase().includes(query)
    );
    displaySearchResults(searchResults);
  });
});
