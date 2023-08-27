const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');
const cardHeading = document.getElementById('cardHeading');
const cardPara = document.getElementById('cardPara');
const cardExtra = document.getElementById('cardExtra');
const cardTag = document.getElementById('cardTag');

// Sample data
const headingsData = [
  {
    heading: 'Totem',
    para: 'Para for Heading 1',
    extra: 'Extra for Heading 1',
    tag: 'Tag for Heading 1'
  },
  {
    heading: 'Trident',
    para: 'Para for Heading 2',
    extra: 'Extra for Heading 2',
    tag: 'Tag for Heading 2'
  },
  {
    heading: 'Temperature',
    para: 'Para for Heading 3',
    extra: 'Extra for Heading 3',
    tag: 'Tag for Heading 3'
  },
  {
    heading: 'Tantrum',
    para: 'Para for Heading 4',
    extra: 'Extra for Heading 4',
    tag: 'Tag for Heading 4'
  }
  // Add more headings as needed
];

// Function to display search results as a list
function displaySearchResults(results) {
  searchResultsContainer.innerHTML = '';

  results.forEach(item => {
    const resultItem = document.createElement('div');
    resultItem.textContent = item.heading;
    resultItem.className = 'search-result';

    resultItem.addEventListener('click', () => {
      updateCardContent(item);
    });

    searchResultsContainer.appendChild(resultItem);
  });
}

// Function to update card content
function updateCardContent(item) {
  cardHeading.textContent = item.heading;
  cardPara.textContent = item.para;
  cardExtra.textContent = item.extra;
  cardTag.textContent = item.tag;
}

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  if (query === '') {
    // Clear the search results container if the search bar is empty
    searchResultsContainer.innerHTML = '';
  } else {
    const searchResults = headingsData.filter(item =>
      item.heading.toLowerCase().includes(query)
    );
    displaySearchResults(searchResults);
  }
});

