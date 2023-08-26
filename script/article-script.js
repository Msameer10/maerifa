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

// Function to display search suggestions
function displaySearchSuggestions(suggestions) {
  searchSuggestions.innerHTML = ''; // Clear previous suggestions
  
  if (suggestions.length === 0) {
    searchSuggestions.style.display = 'none';
    return;
  }
  
  suggestions.forEach(article => {
    const suggestion = document.createElement('div');
    suggestion.className = 'suggestion';
    suggestion.textContent = article.title;
    
    suggestion.addEventListener('click', () => {
      window.location.href = article.url; // Navigate to the selected article
    });
    
    searchSuggestions.appendChild(suggestion);
  });
  
  searchSuggestions.style.display = 'block';
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
