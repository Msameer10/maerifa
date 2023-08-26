const searchInput = document.getElementById('searchInput');
const articleList = document.getElementById('articleList');

// Function to fetch article data from data.json
async function fetchArticleData() {
  try {
    const response = await fetch('../data.json'); // Change the path if needed
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching article data:', error);
    return [];
  }
}

// Function to display search results as a dropdown
function displaySearchResults(results) {
  articleList.innerHTML = ''; // Clear existing results

  results.forEach(article => {
    const option = document.createElement('option');
    option.value = article.title;
    articleList.appendChild(option);
  });
}

// Search input event listener
searchInput.addEventListener('input', async () => {
  const query = searchInput.value.toLowerCase();

  const articles = await fetchArticleData();

  const searchResults = articles.filter(article =>
    article.title.toLowerCase().includes(query)
  );

  displaySearchResults(searchResults);
});

// Click event listener for suggestions
articleList.addEventListener('input', async (event) => {
  const selectedTitle = event.target.value;

  const articles = await fetchArticleData();

  const selectedArticle = articles.find(article =>
    article.title.toLowerCase() === selectedTitle.toLowerCase()
  );

  if (selectedArticle) {
    window.location.href = selectedArticle.url; // Navigate to the selected article
  }
});
