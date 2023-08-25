const cardContainer = document.getElementById('cardContainer');
const searchInput = document.getElementById('searchInput');

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
    <a href="${article.url}" target="_blank">
      <img src="${article.imageUrl}" class="card-img-top" alt="${article.title}">
      <div class="card-body">
        <h5 class="card-title">${article.title}</h5>
      </div>
    </a>
  `;
  cardContainer.appendChild(card);
}

// Display all articles initially
async function displayAllArticles() {
  const articles = await fetchArticleData();
  articles.slice(0, 4).forEach(article => {
    createArticleCard(article);
  });
}

// Create article cards on page load
displayAllArticles();

// Search input event listener
searchInput.addEventListener('input', async () => {
  const articles = await fetchArticleData();
  const query = searchInput.value.toLowerCase();

  cardContainer.innerHTML = ''; // Clear existing cards

  articles
    .filter(article => article.title.toLowerCase().includes(query))
    .slice(0, 4)
    .forEach(article => {
      createArticleCard(article);
    });
});
