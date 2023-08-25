const cardContainer = document.getElementById('cardContainer');
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');

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
async function createArticleCards(query = '') {
  const articles = await fetchArticleData();

  cardContainer.innerHTML = '';

  articles.forEach(article => {
    if (article.title.toLowerCase().includes(query.toLowerCase())) {
      const card = document.createElement('div');
      card.className = 'card mb-3';
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
  });
}

// Create article cards on page load
createArticleCards();

// Search button click event listener
searchButton.addEventListener('click', () => {
  createArticleCards(searchInput.value);
});

// Search input event listener
searchInput.addEventListener('input', () => {
  createArticleCards(searchInput.value);
});
