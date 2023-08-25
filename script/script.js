const cardContainer = document.getElementById('cardContainer');
const contentContainer = document.getElementById('contentContainer');
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');

let articlesData = []; // Store fetched articles data

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

// Function to create article cards
function createArticleCard(article) {
  const card = document.createElement('div');
  card.className = 'card mb-3';
  card.style.marginRight = '10px'; // Add margin for horizontal gap between cards
  card.innerHTML = `
    <div class="card-body">
      <h5 class="card-title">${article.title}</h5>
      <p class="card-text">${article.summary}</p>
      <button class="btn btn-primary read-more-btn" data-article-url="${article.url}">Read More</button>
    </div>
  `;
  cardContainer.appendChild(card);
}

// Function to load article page content
async function loadArticlePage(articleUrl) {
  try {
    const response = await fetch(articleUrl);
    const articleContent = await response.text();
    contentContainer.innerHTML = articleContent;
  } catch (error) {
    console.error('Error loading article content:', error);
  }
}

// Display randomized articles on page load
async function displayRandomizedArticles() {
  articlesData = await fetchArticleData();

  // Randomize the articles array
  const randomizedArticles = articlesData.sort(() => Math.random() - 0.5);

  cardContainer.innerHTML = ''; // Clear existing cards

  randomizedArticles.slice(0, 4).forEach(article => {
    createArticleCard(article);
  });
}

// Create article cards on page load
displayRandomizedArticles();

// Click event listener to navigate to individual article pages
cardContainer.addEventListener('click', async (event) => {
  const clickedButton = event.target.closest('.read-more-btn');
  if (clickedButton) {
    const articleUrl = clickedButton.getAttribute('data-article-url');
    await loadArticlePage(articleUrl); // Load the article page content
    cardContainer.style.display = 'none';
    contentContainer.style.display = 'block';
  }
});

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  cardContainer.innerHTML = ''; // Clear existing cards

  articlesData
    .filter(article => article.title.toLowerCase().includes(query))
    .slice(0, 4)
    .forEach(article => {
      createArticleCard(article);
    });
});
