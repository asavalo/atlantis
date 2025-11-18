// Common JavaScript functionality shared between card and table layouts

// Cache status functionality
function updateCacheStatus() {
    const statusElement = document.getElementById('cache-status');

    if (!statusElement) {
        console.error('Cache status element not found');
        return;
    }

    if (!window.cacheData || window.cacheData.cache_disabled) {
        statusElement.textContent = 'Cache disabled - always fresh data';
        statusElement.style.color = '#6c757d';
        return;
    }

    // Calculate current elapsed time
    const currentTime = Date.now() / 1000;
    const elapsed = currentTime - window.cacheData.last_scan;
    const remaining = Math.max(0, window.cacheData.cache_duration - elapsed);

    // Calculate cache age percentage for color coding
    const agePercentage = elapsed / window.cacheData.cache_duration;

    // Determine color based on cache age
    let color;
    if (agePercentage < 0.6) {
        color = '#198754'; // Green - fresh
    } else if (agePercentage < 0.9) {
        color = '#fd7e14'; // Orange - aging
    } else {
        color = '#dc3545'; // Red - stale
    }

    // Helper function to format time
    function formatTimeAgo(seconds) {
        if (seconds < 60) {
            return Math.floor(seconds) + 's';
        } else if (seconds < 3600) {
            return Math.floor(seconds / 60) + 'm ' + Math.floor(seconds % 60) + 's';
        } else {
            return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
        }
    }

    // Update status text and color
    if (remaining > 0) {
        statusElement.textContent = `Last updated: ${formatTimeAgo(elapsed)} ago (refresh in ${formatTimeAgo(remaining)})`;
    } else {
        statusElement.textContent = `Last updated: ${formatTimeAgo(elapsed)} ago (refresh on next request)`;
        color = '#dc3545'; // Red for expired
    }

    statusElement.style.color = color;

    // Auto-refresh when cache expires
    if (remaining <= 0 && elapsed > window.cacheData.cache_duration) {
        statusElement.textContent = 'Refreshing...';
        statusElement.style.color = '#6c757d';
        setTimeout(() => {
            window.location.reload();
        }, 500);
    }
}

// Date switching functionality
function switchDate(selectedDate) {
    if (selectedDate) {
        window.location.href = `/date/${selectedDate}/`;
    }
}

// Git info modal functionality
function showGitInfoModal() {
    const modal = document.getElementById('git-info-modal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function hideGitInfoModal() {
    const modal = document.getElementById('git-info-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
    const gitModal = document.getElementById('git-info-modal');
    const linksModal = document.getElementById('links-modal');

    if (gitModal && event.target === gitModal) {
        hideGitInfoModal();
    }

    if (linksModal && event.target === linksModal) {
        hideLinksModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        hideGitInfoModal();
        hideLinksModal();
    }
});

// Links modal functionality
function showLinksModal(target, harnessName, harnessUrl, repoUrl, baseCommit) {
    const modal = document.getElementById('links-modal');
    const modalBody = document.getElementById('links-modal-body');
    const modalTitle = modal.querySelector('.modal-header h3');

    if (!modal || !modalBody) return;

    // Update modal title
    if (modalTitle) {
        modalTitle.textContent = `${target} - ${harnessName} Links`;
    }

    // Clear existing content
    modalBody.innerHTML = '';

    // Define the links data
    const links = [
        {
            description: 'Project YAML',
            url: `https://github.com/Team-Atlanta/oss-fuzz/tree/main/projects/${target}/project.yaml`,
            available: true
        },
        {
            description: 'Config YAML',
            url: `https://github.com/Team-Atlanta/oss-fuzz/tree/main/projects/${target}/.aixcc/config.yaml`,
            available: true
        },
        {
            description: 'ref.diff Diff File',
            url: `https://github.com/Team-Atlanta/oss-fuzz/tree/main/projects/${target}/.aixcc/ref.diff`,
            available: true
        },
        {
            description: 'Harness PoVs',
            url: `https://github.com/Team-Atlanta/oss-fuzz/tree/main/projects/${target}/.aixcc/povs/${harnessName}`,
            available: true
        },
        {
            description: 'Harness PoVs - Crash Logs',
            url: `https://github.com/Team-Atlanta/oss-fuzz/tree/main/projects/${target}/.aixcc/crash_logs/${harnessName}`,
            available: true
        },
        {
            description: 'Harness URL',
            url: harnessUrl,
            available: harnessUrl && harnessUrl.trim() !== ''
        },
        {
            description: 'Target Source',
            url: repoUrl && baseCommit ? `${repoUrl}/tree/${baseCommit}` : repoUrl,
            available: repoUrl && repoUrl.trim() !== ''
        }
    ];

    // Populate the modal with links
    links.forEach(link => {
        const row = document.createElement('tr');

        const descCell = document.createElement('td');
        descCell.className = 'repo-name';
        descCell.textContent = link.description;

        const urlCell = document.createElement('td');
        urlCell.className = 'commit-hash';
        urlCell.style.wordWrap = 'break-word';
        urlCell.style.maxWidth = '400px';

        if (link.available) {
            // Make URL text clickable
            const urlLink = document.createElement('a');
            urlLink.href = link.url;
            urlLink.target = '_blank';
            urlLink.textContent = link.url;
            urlLink.style.color = 'inherit';
            urlLink.style.textDecoration = 'underline';
            urlCell.appendChild(urlLink);
        } else {
            urlCell.textContent = 'Not available';
            urlCell.style.color = '#6c757d';
        }

        const linkCell = document.createElement('td');
        linkCell.className = 'repo-link';
        if (link.available) {
            const linkElement = document.createElement('a');
            linkElement.href = link.url;
            linkElement.target = '_blank';
            linkElement.className = 'git-link';
            linkElement.textContent = 'View 🔗';
            linkCell.appendChild(linkElement);
        } else {
            linkCell.textContent = '-';
            linkCell.style.color = '#6c757d';
        }

        row.appendChild(descCell);
        row.appendChild(urlCell);
        row.appendChild(linkCell);
        modalBody.appendChild(row);
    });

    modal.style.display = 'flex';
}

function hideLinksModal() {
    const modal = document.getElementById('links-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    updateCacheStatus();

    // Update cache status every second for real-time countdown
    setInterval(updateCacheStatus, 1000);
});
