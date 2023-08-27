const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');
const cardContainer = document.getElementById('cardContainer');

// Function to fetch headings data from headings.json
async function fetchHeadingsData() {
  try {
    const response = await fetch('headings.json'); // Change the path to match the correct location
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching headings data:', error);
    return [];
  }
}

// Function to display search results as a dropdown
function displaySearchResults(results) {
  searchResultsContainer.innerHTML = ''; // Clear existing results

  results.forEach(item => {
    const resultItem = document.createElement('div');
    resultItem.className = 'search-result';
    resultItem.textContent = item.heading;

    resultItem.addEventListener('click', () => {
      displayCardDetails(item);
    });

    searchResultsContainer.appendChild(resultItem);
  });
}

// Function to display card details
function displayCardDetails(item) {
  cardContainer.innerHTML = `
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">${item.heading}</h5>
        <p class="card-text">${item.definition}</p>
        <p class="card-text">${item.extra}</p>
        <p class="card-text">${item.tag}</p>
      </div>
    </div>
  `;
}

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  if (query === '') {
    // Clear the search results container if the search bar is empty
    searchResultsContainer.innerHTML = '';
  } else {
    fetchHeadingsData().then(headingsData => {
      const searchResults = headingsData.filter(item =>
        item.heading.toLowerCase().includes(query)
      );
      displaySearchResults(searchResults);
    });
  }
});

// Click event listener on the document to clear search results
document.addEventListener('click', (event) => {
  if (event.target !== searchInput) {
    // Clear the search results container when clicking outside the search bar
    searchResultsContainer.innerHTML = '';
  }
});

// Display default card details on page load
const defaultCard = {
  heading: "Default Heading",
  definition: "This is the default definition.",
  extra: "No extra information available.",
  tag: "Default Tag"
};

displayCardDetails(defaultCard);
