// Table-specific JavaScript functionality for index_table.html

// Global variables for sorting
let statsTableSortState = { column: 'matched', direction: 'asc' };
let experimentsTableSortState = { column: 'matched', direction: 'asc' };

// Helper function to extract numeric value from text
function extractNumericValue(text) {
    if (!text || text === '-') return 0;
    const match = text.toString().replace(/[,$]/g, '').match(/[\d.]+/);
    return match ? parseFloat(match[0]) : 0;
}

// Helper function to extract success rate from matched column
function extractSuccessRate(cell) {
    const rateSpan = cell.querySelector('.pov-rate');
    if (!rateSpan) return 0;
    const rateText = rateSpan.textContent;
    const match = rateText.match(/(\d+)%/);
    return match ? parseInt(match[1]) : 0;
}

// Enhanced function to extract composite sorting value from matched column
function extractMatchedSortValue(cell) {
    // Check if this is an incomplete experiment (shows "-")
    const incompleteSpan = cell.querySelector('.status-incomplete');
    if (incompleteSpan) {
        return -1; // Sort incomplete experiments last
    }

    // Extract percentage from .pov-rate span
    const rateSpan = cell.querySelector('.pov-rate');
    let percentage = 0;
    if (rateSpan) {
        const rateText = rateSpan.textContent;
        const percentMatch = rateText.match(/(\d+)%/);
        if (percentMatch) {
            percentage = parseInt(percentMatch[1]);
        }
    }

    // Extract matched count from .pov-main span
    const mainSpan = cell.querySelector('.pov-main');
    let matchedCount = 0;
    if (mainSpan) {
        const mainText = mainSpan.textContent;
        const matchedMatch = mainText.match(/(\d+)\/\d+/);
        if (matchedMatch) {
            matchedCount = parseInt(matchedMatch[1]);
        }
    }

    // Create composite value: percentage * 1000 + matched count
    // This ensures percentage is primary sort, matched count is secondary
    return (percentage * 1000) + matchedCount;
}

// Helper function to check if an experiment row is incomplete
function isExperimentIncomplete(row) {
    return row.querySelector('.status-not-started') !== null;
}

// Helper function to create two-tier sort value (completion status + column value)
function createTwoTierSortValue(row, columnValue, isStatusColumn = false) {
    // For status column, use normal sorting
    if (isStatusColumn) {
        return columnValue;
    }

    // For all other columns, prioritize complete/running experiments
    const isIncomplete = isExperimentIncomplete(row);

    if (typeof columnValue === 'string') {
        // For string values, incomplete experiments get a high sort value to appear last
        return isIncomplete ? 'zzz_' + columnValue : 'aaa_' + columnValue;
    } else {
        // For numeric values, use a large offset to separate complete from incomplete
        return isIncomplete ? columnValue - 1000000 : columnValue + 1000000;
    }
}

// Sorting functionality for stats table
function sortStatsTable(column) {
    const tbody = document.querySelector('.stats-table tbody');
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll('.stats-table-row:not(.total-row)'));
    const totalRow = tbody.querySelector('.stats-table-row.total-row');

    // Toggle sort direction
    if (statsTableSortState.column === column) {
        statsTableSortState.direction = statsTableSortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
        statsTableSortState.column = column;
        statsTableSortState.direction = 'asc';
    }

    rows.sort((a, b) => {
        let aValue, bValue;

        switch (column) {
            case 'combo':
                aValue = a.querySelector('.combo-name').textContent.trim();
                bValue = b.querySelector('.combo-name').textContent.trim();
                break;
            case 'finished':
                aValue = extractNumericValue(a.querySelector('.experiment-count').textContent.split('/')[0]);
                bValue = extractNumericValue(b.querySelector('.experiment-count').textContent.split('/')[0]);
                break;
            case 'matched':
                aValue = extractMatchedSortValue(a.querySelector('.matched-expected'));
                bValue = extractMatchedSortValue(b.querySelector('.matched-expected'));
                break;
            case 'total':
                aValue = extractNumericValue(a.querySelector('.total-found').textContent);
                bValue = extractNumericValue(b.querySelector('.total-found').textContent);
                break;
            case 'cost':
                aValue = extractNumericValue(a.querySelector('.litellm-cost').textContent);
                bValue = extractNumericValue(b.querySelector('.litellm-cost').textContent);
                break;
            case 'tokens':
                aValue = extractNumericValue(a.querySelector('.litellm-tokens').textContent);
                bValue = extractNumericValue(b.querySelector('.litellm-tokens').textContent);
                break;
            case 'cache':
                aValue = extractNumericValue(a.querySelector('.litellm-cache').textContent);
                bValue = extractNumericValue(b.querySelector('.litellm-cache').textContent);
                break;
            case 'reqs':
                aValue = extractNumericValue(a.querySelector('.litellm-requests').textContent.split('/')[0]);
                bValue = extractNumericValue(b.querySelector('.litellm-requests').textContent.split('/')[0]);
                break;
            default:
                return 0;
        }

        if (typeof aValue === 'string') {
            return statsTableSortState.direction === 'asc' ?
                aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
        } else {
            return statsTableSortState.direction === 'asc' ?
                aValue - bValue : bValue - aValue;
        }
    });

    // Clear tbody and re-append sorted rows
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
    if (totalRow) tbody.appendChild(totalRow);
}

// Sorting functionality for experiments table
function sortExperimentsTable(column) {
    const tbody = document.getElementById('experiments-table-body');
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll('.experiment-row'));

    // Toggle sort direction
    if (experimentsTableSortState.column === column) {
        experimentsTableSortState.direction = experimentsTableSortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
        experimentsTableSortState.column = column;
        experimentsTableSortState.direction = 'asc';
    }

    rows.sort((a, b) => {
        let aValue, bValue;

        switch (column) {
            case 'status':
                // Three-state sorting: complete (2) > running (1) > not-started (0)
                if (a.querySelector('.status-complete')) {
                    aValue = 2;
                } else if (a.querySelector('.status-running')) {
                    aValue = 1;
                } else {
                    aValue = 0;
                }

                if (b.querySelector('.status-complete')) {
                    bValue = 2;
                } else if (b.querySelector('.status-running')) {
                    bValue = 1;
                } else {
                    bValue = 0;
                }
                // Status column uses normal sorting (no two-tier)
                break;
            case 'target':
                aValue = createTwoTierSortValue(a, a.querySelector('.target-cell').textContent.trim());
                bValue = createTwoTierSortValue(b, b.querySelector('.target-cell').textContent.trim());
                break;
            case 'harness':
                aValue = createTwoTierSortValue(a, a.querySelector('.harness-cell').textContent.trim());
                bValue = createTwoTierSortValue(b, b.querySelector('.harness-cell').textContent.trim());
                break;
            case 'input-gens':
                aValue = createTwoTierSortValue(a, a.querySelector('.input-gens-cell').textContent.trim());
                bValue = createTwoTierSortValue(b, b.querySelector('.input-gens-cell').textContent.trim());
                break;
            case 'matched':
                // For matched column, we still use the special logic but apply two-tier sorting
                const aMatchedValue = extractMatchedSortValue(a.querySelector('.matched-expected-cell'));
                const bMatchedValue = extractMatchedSortValue(b.querySelector('.matched-expected-cell'));
                aValue = createTwoTierSortValue(a, aMatchedValue);
                bValue = createTwoTierSortValue(b, bMatchedValue);
                break;
            case 'llm':
                aValue = createTwoTierSortValue(a, extractNumericValue(a.querySelector('.llm-cost-cell').textContent));
                bValue = createTwoTierSortValue(b, extractNumericValue(b.querySelector('.llm-cost-cell').textContent));
                break;
            default:
                return 0;
        }

        if (typeof aValue === 'string') {
            return experimentsTableSortState.direction === 'asc' ?
                aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
        } else {
            return experimentsTableSortState.direction === 'asc' ?
                aValue - bValue : bValue - aValue;
        }
    });

    // Clear tbody and re-append sorted rows
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
}

// Global variable to track current filter
let currentInputGenFilter = null;

// Stats table row click functionality for filtering
function handleStatsRowClick(event) {
    const row = event.currentTarget;
    const inputGens = row.dataset.inputGens;

    if (!inputGens) return;

    // Toggle filter: if clicking the same row, clear filter
    if (currentInputGenFilter === inputGens) {
        clearInputGenFilter();
    } else {
        applyInputGenFilter(inputGens);
    }
}

// Apply input generator filter to detailed table
function applyInputGenFilter(inputGens) {
    currentInputGenFilter = inputGens;

    // Update summary table visual state
    const statsRows = document.querySelectorAll('.stats-table-row:not(.total-row)');
    statsRows.forEach(row => {
        if (row.dataset.inputGens === inputGens) {
            row.classList.add('selected');
        } else {
            row.classList.remove('selected');
        }
    });

    // Remove total row indicator when filtering
    const totalRow = document.querySelector('.stats-table-row.total-row');
    if (totalRow) {
        totalRow.classList.remove('selected');
    }

    // Filter detailed table rows
    const detailedRows = document.querySelectorAll('.experiment-row');
    detailedRows.forEach(row => {
        const rowInputGens = row.dataset.inputGens;
        if (rowInputGens === inputGens) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Clear input generator filter
function clearInputGenFilter() {
    currentInputGenFilter = null;

    // Clear summary table selection
    const statsRows = document.querySelectorAll('.stats-table-row:not(.total-row)');
    statsRows.forEach(row => row.classList.remove('selected'));

    // Show total row indicator when no filtering
    const totalRow = document.querySelector('.stats-table-row.total-row');
    if (totalRow) {
        totalRow.classList.add('selected');
    }

    // Show all detailed table rows
    const detailedRows = document.querySelectorAll('.experiment-row');
    detailedRows.forEach(row => {
        row.style.display = '';
    });
}

// Total row click functionality
function handleTotalRowClick(event) {
    const row = event.currentTarget;

    // Always clear any active filter when total row is clicked
    if (currentInputGenFilter) {
        clearInputGenFilter();
    }
    // If no filter was active, the total row will already show the indicator
}

// Update the total row to always show "show all" indicator
function updateTotalRowIndicator() {
    const totalRow = document.querySelector('.stats-table-row.total-row');
    if (totalRow) {
        totalRow.classList.add('selected');
    }
}

// Initialize table-specific functionality
function initializeTableFunctionality() {
    // Add click handlers to stats table rows (excluding total row)
    const statsRows = document.querySelectorAll('.stats-table-row:not(.total-row)');
    statsRows.forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', handleStatsRowClick);
    });

    // Add click handler to total row
    const totalRow = document.querySelector('.stats-table-row.total-row');
    if (totalRow) {
        totalRow.style.cursor = 'pointer';
        totalRow.addEventListener('click', handleTotalRowClick);
    }

    // Add click handlers to Links buttons
    const linksButtons = document.querySelectorAll('.links-btn');
    linksButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            const target = this.dataset.target;
            const harnessName = this.dataset.harnessName;
            const harnessUrl = this.dataset.harnessUrl;
            const repoUrl = this.dataset.repoUrl;
            const baseCommit = this.dataset.baseCommit;
            showLinksModal(target, harnessName, harnessUrl, repoUrl, baseCommit);
        });
    });

    // Always show "show all" indicator on total row
    updateTotalRowIndicator();

    // Sort both tables by "matched" in descending order by default
    sortStatsTable("matched");
    sortExperimentsTable("matched");
}


// Finder Statistics Modal Functions
function showFinderStatsModal(experimentName) {
    const modal = document.getElementById('finder-stats-modal');
    const content = document.getElementById('finder-stats-content');

    if (!modal || !content) return;

    // Find the report data for this experiment
    const reportData = window.reportsData.find(report => report.experiment_name === experimentName);

    if (!reportData || !reportData.finder_stats) {
        content.innerHTML = '<p>No finder statistics available for this experiment.</p>';
        modal.style.display = 'block';
        return;
    }

    // Create summary
    const finderStats = reportData.finder_stats;
    const totalPovs = finderStats.reduce((sum, stat) => sum + stat.pov_count, 0);
    const totalMatchedPovs = finderStats.reduce((sum, stat) => sum + stat.matched_pov_count, 0);
    const totalUnintendedPovs = finderStats.reduce((sum, stat) => sum + stat.unintended_pov_count, 0);
    const totalSeeds = finderStats.reduce((sum, stat) => sum + stat.total_seeds, 0);

    let html = `
        <div class="finder-stats-summary">
            <h4>Experiment: ${experimentName}</h4>
            <p><strong>Total PoVs:</strong> ${totalPovs} | <strong>Matched:</strong> ${totalMatchedPovs} | <strong>Unintended:</strong> ${totalUnintendedPovs} | <strong>Total Seeds:</strong> ${totalSeeds}</p>
        </div>

        <table class="finder-stats-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>PoVs</th>
                    <th>Unintended</th>
                    <th>Seeds</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
    `;

    // Sort finders by name
    const sortedStats = finderStats.sort((a, b) => a.finder_name.localeCompare(b.finder_name));

    sortedStats.forEach(stat => {
        const cleanName = stat.finder_name.replace('_input_gen', '');
        const seeds = stat.others_corpus_count + stat.uniafl_corpus_count;
        html += `
            <tr>
                <td>${cleanName}</td>
                <td class="pov-count">${stat.pov_count}</td>
                <td class="unintended-pov-count">${stat.unintended_pov_count}</td>
                <td class="seeds-count">${seeds}</td>
                <td class="total-seeds">${stat.total_seeds}</td>
            </tr>
        `;
    });

    html += `
            </tbody>
        </table>
    `;

    content.innerHTML = html;
    modal.style.display = 'block';
}

function hideFinderStatsModal() {
    const modal = document.getElementById('finder-stats-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeTableFunctionality();

    // Add event listeners for finder stats buttons
    document.querySelectorAll('.finder-stats-btn:not(.disabled)').forEach(button => {
        button.addEventListener('click', function() {
            const experimentName = this.getAttribute('data-experiment-name');
            showFinderStatsModal(experimentName);
        });
    });

    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        const finderModal = document.getElementById('finder-stats-modal');
        if (event.target === finderModal) {
            hideFinderStatsModal();
        }
    });
});
