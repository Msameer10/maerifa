const searchInputArticle = document.getElementById('searchInputArticle');
const dropdown = document.getElementById('dropdown');

// Function to fetch article data from data.json
async function fetchArticleData() {
  try {
    const response = await fetch('data.json');
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching article data:', error);
    return [];
  }
}

// Function to populate the dropdown with article titles
async function populateDropdown(query) {
  const articles = await fetchArticleData();

  // Filter articles based on query
  const filteredArticles = articles.filter(article =>
    article.title.toLowerCase().includes(query.toLowerCase())
  );

  // Clear existing dropdown options
  dropdown.innerHTML = '';

  // Create and append dropdown options
  filteredArticles.forEach(article => {
    const option = document.createElement('option');
    option.value = article.url;
    option.textContent = article.title;
    dropdown.appendChild(option);
  });
}

// Search input event listener
searchInputArticle.addEventListener('input', () => {
  const query = searchInputArticle.value;
  populateDropdown(query);
});

// Dropdown change event listener
dropdown.addEventListener('change', () => {
  const selectedUrl = dropdown.value;
  if (selectedUrl) {
    window.location.href = selectedUrl; // Navigate to the selected article page
  }
});
