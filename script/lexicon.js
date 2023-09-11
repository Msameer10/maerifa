const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');
const cardHeading = document.getElementById('cardHeading');
const cardPara = document.getElementById('cardPara');
const cardExtra = document.getElementById('cardExtra');
const cardTag = document.getElementById('cardTag');

// Sample data
const headingsData = [
  {
    heading: 'Armageddon',
    para: 'Armageddon is a term that refers to a catastrophic and apocalyptic event or conflict of immense proportions, often associated with the end of the world or a major showdown between opposing forces.',
    extra: 'In religious contexts, Armageddon is mentioned as a final battle between good and evil in some belief systems, particularly in Christian theology.',
    tags: ['Apocalypse', 'End Times', 'Eschatology']
  },
  {
    heading: 'Narcotics',
    para: 'Narcotics are a category of drugs that primarily include substances derived from opium poppy plants, such as heroin, morphine, and codeine. These drugs have strong pain-relieving properties and are often used for medical purposes, but they can also have a high potential for abuse and addiction.',
    extra: 'The term "narcotics" is sometimes used more broadly to refer to any illegal or controlled substances, including not only opiate-based drugs but also cocaine, marijuana, and synthetic drugs.',
    tags: ['Drugs', 'Opioids', 'Addiction']
  },
  {
    heading: 'Narcissism',
    para: 'Narcissism is a psychological term that refers to a personality trait or disorder characterized by an excessive focus on oneself, one's appearance, abilities, or achievements, often accompanied by a lack of empathy for others and a constant need for admiration and validation.',
    extra: 'Narcissism can range from a healthy level of self-confidence and self-esteem to pathological narcissism, such as narcissistic personality disorder (NPD), which is a more severe and rigid condition.',
    tags: ['Psychology', 'Personality Trait', 'Narcissistic Personality Disorder']
  },
  {
    heading: 'Narcissist',
    para: 'A narcissist is an individual who displays excessive self-love, self-importance, and an exaggerated sense of their own abilities and achievements. They often lack empathy for others and seek constant admiration and validation from those around them.',
    extra: 'Narcissistic personality disorder (NPD) is a psychological condition characterized by a pervasive pattern of narcissistic behavior and a profound need for attention and admiration.',
    tags: ['Psychology', 'Personality Disorder', 'Narcissism']
  },
  // Add more headings as needed
];

// Function to display search results as a list
function displaySearchResults(results) {
  if (!results.length) {
    searchResultsContainer.innerHTML = '';
    return;
  }

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

  if (!query.trim()) {
    searchResultsContainer.innerHTML = ''; // Clear the search results container
    return;
  }

  const searchResults = headingsData.filter(item =>
    item.heading.toLowerCase().includes(query)
  );

  displaySearchResults(searchResults);
});

// Blur event listener for the search input
searchInput.addEventListener('blur', () => {
  // Delay clearing the search results to allow user interaction
  setTimeout(() => {
    searchResultsContainer.innerHTML = '';
  }, 200);
});