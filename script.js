const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');

async function fetchArticleData() {
  try {
    const response = await fetch('adata.json');
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching article data:', error);
    return [];
  }
}

function displaySearchResults(results) {
  searchResultsContainer.innerHTML = '';

  results.forEach(article => {
    const resultItem = document.createElement('option');
    resultItem.textContent = article.title;
    searchResultsContainer.appendChild(resultItem);
  });
}

searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  fetchArticleData().then(articles => {
    const searchResults = articles.filter(article =>
      article.title.toLowerCase().includes(query)
    );
    displaySearchResults(searchResults);
  });
});
