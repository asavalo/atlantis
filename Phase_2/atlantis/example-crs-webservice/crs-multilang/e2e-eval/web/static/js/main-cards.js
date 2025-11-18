// Card-specific JavaScript functionality for index.html

// Global state for current filter
let currentFilter = null;

// Sorting functionality for experiment cards
function sortExperiments(sortBy) {
    const container = document.getElementById('experiments-container');
    if (!container) return;

    const cards = Array.from(container.children);

    cards.sort((a, b) => {
        let aValue, bValue;

        if (sortBy === 'target') {
            aValue = a.dataset.target || '';
            bValue = b.dataset.target || '';
        } else if (sortBy === 'input-gen') {
            aValue = a.dataset.inputGens || '';
            bValue = b.dataset.inputGens || '';
        } else if (sortBy === 'harness') {
            aValue = a.dataset.harness || '';
            bValue = b.dataset.harness || '';
        }

        return aValue.localeCompare(bValue);
    });

    // Re-append sorted cards
    cards.forEach(card => container.appendChild(card));
}

// Client-side filter function for dropdown
function applyFilterFromDropdown(hashValue) {
    if (hashValue) {
        // Find the corresponding input generators for this hash
        const matchingCombo = window.uniqueCombinations?.find(combo => combo.hash === hashValue);
        if (matchingCombo) {
            applyClientSideFilter(matchingCombo.input_gens);
        }
    } else {
        clearClientSideFilter();
    }
}

// Main client-side filtering function
function applyClientSideFilter(inputGens) {
    // Update visual selection in stats table
    updateStatsRowSelection(inputGens);

    // Filter experiment cards (client-side only)
    filterExperimentCards(inputGens);

    // Update URL without reload
    updateUrlWithoutReload(inputGens);

    // Update filter dropdown
    updateFilterDropdown(inputGens);

    // Store current filter
    currentFilter = inputGens;
}

function updateStatsRowSelection(selectedInputGens) {
    // Remove previous selection from all stats rows
    const allRows = document.querySelectorAll('.stats-table-row[data-input-gens], .stats-table-row.total-row');
    allRows.forEach(row => row.classList.remove('selected'));

    if (selectedInputGens) {
        // When filtering: only mark the specific row as selected
        const selectedRow = document.querySelector(`.stats-table-row[data-input-gens="${selectedInputGens}"]`);
        if (selectedRow) {
            selectedRow.classList.add('selected');
        }
    } else {
        // When no filter: only mark the total row as selected (showing all experiments)
        const totalRow = document.querySelector('.stats-table-row.total-row');
        if (totalRow) {
            totalRow.classList.add('selected');
        }
    }
}

function filterExperimentCards(inputGens) {
    const experimentCards = document.querySelectorAll('.experiment-card');
    let visibleCount = 0;

    experimentCards.forEach(card => {
        const cardInputGens = card.getAttribute('data-input-gens');

        if (!inputGens || cardInputGens === inputGens) {
            card.style.display = 'block';
            visibleCount++;
            // Update index number for visible cards
            const indexElement = card.querySelector('.experiment-index');
            if (indexElement) {
                indexElement.textContent = `#${visibleCount}`;
            }
        } else {
            card.style.display = 'none';
        }
    });

    console.log(`Filtered to ${visibleCount} experiments`);
}

function updateUrlWithoutReload(inputGens) {
    const url = new URL(window.location);
    url.searchParams.delete('hash');
    url.searchParams.delete('input_gens');

    if (inputGens) {
        url.searchParams.set('input_gens', inputGens);
    }

    // Update URL without reload
    history.pushState({}, '', url.toString());
}

function updateFilterDropdown(inputGens) {
    const filterSelect = document.getElementById('filter-select');
    if (filterSelect && window.uniqueCombinations) {
        if (inputGens) {
            const matchingCombo = window.uniqueCombinations.find(combo => combo.input_gens === inputGens);
            if (matchingCombo) {
                filterSelect.value = matchingCombo.hash;
            }
        } else {
            filterSelect.value = '';
        }
    }
}

function clearClientSideFilter() {
    // Clear visual selection
    updateStatsRowSelection(null);

    // Show all experiment cards
    filterExperimentCards(null);

    // Update URL
    updateUrlWithoutReload(null);

    // Update dropdown
    updateFilterDropdown(null);

    // Clear current filter
    currentFilter = null;
}

// Legacy functions (kept for compatibility)
function clearFilter() {
    clearClientSideFilter();
}

function filterByHash(hash) {
    const matchingCombo = window.uniqueCombinations?.find(combo => combo.hash === hash);
    if (matchingCombo) {
        applyClientSideFilter(matchingCombo.input_gens);
    }
}

function filterByInputGens(inputGens) {
    applyClientSideFilter(inputGens);
}

function filterByStatsRow(inputGens) {
    applyClientSideFilter(inputGens);
}

// Stats table row click functionality
function handleStatsRowClick(event) {
    const row = event.currentTarget;
    const inputGens = row.dataset.inputGens;

    if (inputGens) {
        applyClientSideFilter(inputGens);
    } else if (row.classList.contains('total-row')) {
        clearClientSideFilter();
    }
}

// Initialize client-side filtering on page load
function initializeClientSideFiltering() {
    // Check if there are URL parameters for filtering
    const urlParams = new URLSearchParams(window.location.search);
    const inputGensParam = urlParams.get('input_gens');
    const hashParam = urlParams.get('hash');

    if (inputGensParam) {
        // Apply filter based on input_gens parameter
        filterByStatsRow(inputGensParam);
    } else if (hashParam && window.uniqueCombinations) {
        // Apply filter based on hash parameter
        const matchingCombo = window.uniqueCombinations.find(combo => combo.hash === hashParam);
        if (matchingCombo) {
            filterByStatsRow(matchingCombo.input_gens);
        }
    } else {
        // No filters applied - mark total row as selected by default
        updateStatsRowSelection(null);
    }
}

// Initialize card-specific functionality
function initializeCardFunctionality() {
    // Add click handlers to stats table rows
    const statsRows = document.querySelectorAll('.stats-table-row');
    statsRows.forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', handleStatsRowClick);
    });

    // Initialize client-side filtering
    setTimeout(initializeClientSideFiltering, 100); // Small delay to ensure data is loaded
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCardFunctionality();
});
