const searchInputArticle = document.getElementById('searchInputArticle');
const articleList = document.getElementById('articleList');

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

// Populate the datalist with article titles
async function populateArticleList() {
  const articles = await fetchArticleData();
  articleList.innerHTML = '';

  articles.forEach(article => {
    const option = document.createElement('option');
    option.value = article.title;
    articleList.appendChild(option);
  });
}

// Load the selected article's page
function loadArticlePage(articleTitle) {
  const articles = await fetchArticleData();
  const selectedArticle = articles.find(article => article.title === articleTitle);
  
  if (selectedArticle) {
    window.location.href = selectedArticle.url;
  }
}

// Populate the datalist on page load
populateArticleList();

// Search input event listener
searchInputArticle.addEventListener('input', () => {
  const query = searchInputArticle.value.toLowerCase();
  const matchingArticles = [];

  fetchArticleData().then(articles => {
    articles.forEach(article => {
      if (article.title.toLowerCase().includes(query)) {
        matchingArticles.push(article);
      }
    });

    articleList.innerHTML = '';
    matchingArticles.forEach(matchingArticle => {
      const option = document.createElement('option');
      option.value = matchingArticle.title;
      articleList.appendChild(option);
    });
  });
});

// Event listener to handle selecting an article
searchInputArticle.addEventListener('change', () => {
  loadArticlePage(searchInputArticle.value);
});
