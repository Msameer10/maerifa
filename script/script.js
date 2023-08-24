// Function to perform search
function performSearch(query) {
    const searchResultsSection = document.getElementById("searchResults");
    searchResultsSection.innerHTML = ""; // Clear previous search results

    // Fetch the list of articles from the JSON file
    fetch("articles.json")
        .then(response => response.json())
        .then(data => {
            const articles = data.articles;

            articles.forEach(article => {
                fetch(`articles/${article}`)
                    .then(response => response.text())
                    .then(content => {
                        if (content.toLowerCase().includes(query.toLowerCase())) {
                            const articleElement = document.createElement("article");
                            articleElement.innerHTML = content;
                            searchResultsSection.appendChild(articleElement);
                        }
                    });
            });
        });
}

// Event listener for search button
const searchButton = document.getElementById("searchButton");
searchButton.addEventListener("click", () => {
    const searchInput = document.getElementById("searchInput");
    const query = searchInput.value;
    performSearch(query);
});
