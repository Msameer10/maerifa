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
  card.style.height = '300px'; // Set a fixed height for the card
  card.style.width = '300px';

  card.innerHTML = `
    <div class="clickable-card" data-article-url="${article.url}">
      <img src="${article.imageUrl}" class="card-img-top" alt="${article.title}" style="height: 150px;"> <!-- Set a fixed height for the image -->
      <div class="card-body text-center">
        <h3 class="card-title">${article.title}</h3>
      </div>
    </div>
  `;

  return card; // Return the created card element
}

// Display randomized articles on page load
async function displayRandomizedArticles() {
  const articles = await fetchArticleData();

  // Randomize the articles array
  const randomizedArticles = articles.sort(() => Math.random() - 0.5);

  cardContainer.innerHTML = ''; // Clear existing cards

  randomizedArticles.slice(0, 4).forEach(article => {
    const card = createArticleCard(article);
    cardContainer.appendChild(card);
  });
}

// Create article cards on page load
displayRandomizedArticles();

// Click event listener using event delegation
cardContainer.addEventListener('click', (event) => {
  const clickedCard = event.target.closest('.clickable-card');
  if (clickedCard) {
    const articleUrl = clickedCard.getAttribute('data-article-url');
    window.location.href = articleUrl;
  }
});

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  cardContainer.innerHTML = ''; // Clear existing cards

  fetchArticleData().then(articles => {
    articles
      .filter(article => article.title.toLowerCase().includes(query))
      .slice(0, 4)
      .forEach(article => {
        const card = createArticleCard(article);
        cardContainer.appendChild(card);
      });
  });
});
