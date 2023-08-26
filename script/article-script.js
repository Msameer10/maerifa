const searchInput = document.getElementById('searchInput');
const searchSuggestions = document.getElementById('searchSuggestions');

// Function to fetch article data from data.json
async function fetchArticleData() {
  try {
    const response = await fetch('../adata.json');
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
      const baseUrl = window.location.href.replace(/\/[^\/]*$/, ''); // Get the base URL of the current page
      window.location.href = baseUrl + '/' + article.url; // Navigate to the selected article
    });

    searchResultsContainer.appendChild(resultItem);
  });
}


// Search input event listener
searchInput.addEventListener('input', async () => {
  const query = searchInput.value.toLowerCase();
  
  if (query.trim() === '') {
    searchSuggestions.style.display = 'none';
    return;
  }
  
  const articles = await fetchArticleData();
  const matchingArticles = articles.filter(article =>
    article.title.toLowerCase().includes(query)
  );
  
  displaySearchSuggestions(matchingArticles);
});
