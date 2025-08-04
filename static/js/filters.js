/**
 * Filtering and Search JavaScript for Threat Intel Dashboard
 * Handles advanced filtering, sorting, and search functionality
 */

// Filter state management
let filterState = {
    search: '',
    severity: '',
    source: '',
    tactic: '',
    tags: [],
    dateRange: '',
    sortBy: 'date',
    sortOrder: 'desc',
    page: 1
};

let searchTimeout;
let filterHistory = [];

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeFilters();
});

/**
 * Initialize filter functionality
 */
function initializeFilters() {
    console.log('Initializing filters...');
    
    // Load initial filter state from URL
    loadFilterStateFromURL();
    
    // Set up filter controls
    setupFilterControls();
    
    // Set up search functionality
    setupSearchFunctionality();
    
    // Set up sorting controls
    setupSortingControls();
    
    // Set up advanced filters
    setupAdvancedFilters();
    
    // Apply initial filters
    applyFilters();
}

/**
 * Load filter state from URL parameters
 */
function loadFilterStateFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    
    filterState = {
        search: urlParams.get('search') || '',
        severity: urlParams.get('severity') || '',
        source: urlParams.get('source') || '',
        tactic: urlParams.get('tactic') || '',
        tags: urlParams.get('tags') ? urlParams.get('tags').split(',') : [],
        dateRange: urlParams.get('dateRange') || '',
        sortBy: urlParams.get('sortBy') || 'date',
        sortOrder: urlParams.get('sortOrder') || 'desc',
        page: parseInt(urlParams.get('page')) || 1
    };
    
    // Update form controls to match URL state
    updateFormControlsFromState();
}

/**
 * Update form controls based on current filter state
 */
function updateFormControlsFromState() {
    // Search input
    const searchInput = document.querySelector('input[name="search"]');
    if (searchInput) {
        searchInput.value = filterState.search;
    }
    
    // Filter dropdowns
    const severitySelect = document.querySelector('select[name="severity"]');
    if (severitySelect) {
        severitySelect.value = filterState.severity;
    }
    
    const sourceSelect = document.querySelector('select[name="source"]');
    if (sourceSelect) {
        sourceSelect.value = filterState.source;
    }
    
    const tacticSelect = document.querySelector('select[name="tactic"]');
    if (tacticSelect) {
        tacticSelect.value = filterState.tactic;
    }
    
    // Sort controls
    const sortSelect = document.querySelector('select[name="sortBy"]');
    if (sortSelect) {
        sortSelect.value = filterState.sortBy;
    }
    
    const orderSelect = document.querySelector('select[name="sortOrder"]');
    if (orderSelect) {
        orderSelect.value = filterState.sortOrder;
    }
}

/**
 * Set up filter controls
 */
function setupFilterControls() {
    // Severity filter
    const severityFilter = document.querySelector('select[name="severity"]');
    if (severityFilter) {
        severityFilter.addEventListener('change', function() {
            filterState.severity = this.value;
            filterState.page = 1;
            applyFiltersWithURL();
        });
    }
    
    // Source filter
    const sourceFilter = document.querySelector('select[name="source"]');
    if (sourceFilter) {
        sourceFilter.addEventListener('change', function() {
            filterState.source = this.value;
            filterState.page = 1;
            applyFiltersWithURL();
        });
    }
    
    // Tactic filter
    const tacticFilter = document.querySelector('select[name="tactic"]');
    if (tacticFilter) {
        tacticFilter.addEventListener('change', function() {
            filterState.tactic = this.value;
            filterState.page = 1;
            applyFiltersWithURL();
        });
    }
    
    // Clear filters button
    const clearButton = document.querySelector('.clear-filters');
    if (clearButton) {
        clearButton.addEventListener('click', clearAllFilters);
    }
    
    // Advanced filters toggle
    const advancedToggle = document.querySelector('.advanced-filters-toggle');
    if (advancedToggle) {
        advancedToggle.addEventListener('click', toggleAdvancedFilters);
    }
}

/**
 * Set up search functionality
 */
function setupSearchFunctionality() {
    const searchInput = document.querySelector('input[name="search"]');
    if (!searchInput) return;
    
    // Real-time search with debouncing
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        searchTimeout = setTimeout(() => {
            filterState.search = query;
            filterState.page = 1;
            applyFiltersWithURL();
        }, 300);
    });
    
    // Search form submission
    const searchForm = searchInput.closest('form');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            clearTimeout(searchTimeout);
            filterState.search = searchInput.value.trim();
            filterState.page = 1;
            applyFiltersWithURL();
        });
    }
    
    // Search suggestions
    setupSearchSuggestions(searchInput);
    
    // Search shortcuts
    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            this.value = '';
            filterState.search = '';
            applyFiltersWithURL();
        }
    });
}

/**
 * Set up search suggestions
 */
function setupSearchSuggestions(searchInput) {
    const suggestionsContainer = document.createElement('div');
    suggestionsContainer.className = 'search-suggestions';
    suggestionsContainer.style.display = 'none';
    searchInput.parentNode.appendChild(suggestionsContainer);
    
    let suggestionTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(suggestionTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            hideSuggestions();
            return;
        }
        
        suggestionTimeout = setTimeout(() => {
            fetchSearchSuggestions(query, suggestionsContainer);
        }, 200);
    });
    
    // Hide suggestions when clicking outside
    document.addEventListener('click', function(e) {
        if (!searchInput.contains(e.target) && !suggestionsContainer.contains(e.target)) {
            hideSuggestions();
        }
    });
    
    function hideSuggestions() {
        suggestionsContainer.style.display = 'none';
    }
}

/**
 * Fetch search suggestions
 */
async function fetchSearchSuggestions(query, container) {
    try {
        // Mock suggestions - in real implementation, call API
        const suggestions = [
            'malware',
            'ransomware', 
            'phishing',
            'apt28',
            'credential access',
            'lateral movement'
        ].filter(s => s.toLowerCase().includes(query.toLowerCase()));
        
        displaySuggestions(suggestions, container, query);
    } catch (error) {
        console.warn('Error fetching search suggestions:', error);
    }
}

/**
 * Display search suggestions
 */
function displaySuggestions(suggestions, container, query) {
    if (suggestions.length === 0) {
        container.style.display = 'none';
        return;
    }
    
    container.innerHTML = suggestions.map(suggestion => `
        <div class="suggestion-item" data-suggestion="${suggestion}">
            ${highlightQuery(suggestion, query)}
        </div>
    `).join('');
    
    container.style.display = 'block';
    
    // Add click handlers
    container.querySelectorAll('.suggestion-item').forEach(item => {
        item.addEventListener('click', function() {
            const suggestion = this.dataset.suggestion;
            const searchInput = document.querySelector('input[name="search"]');
            searchInput.value = suggestion;
            filterState.search = suggestion;
            filterState.page = 1;
            applyFiltersWithURL();
            container.style.display = 'none';
        });
    });
}

/**
 * Highlight query in suggestion text
 */
function highlightQuery(text, query) {
    if (!query) return text;
    
    const regex = new RegExp(`(${escapeRegExp(query)})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}

/**
 * Escape special regex characters
 */
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Set up sorting controls
 */
function setupSortingControls() {
    const sortSelect = document.querySelector('select[name="sortBy"]');
    if (sortSelect) {
        sortSelect.addEventListener('change', function() {
            filterState.sortBy = this.value;
            applyFiltersWithURL();
        });
    }
    
    const orderSelect = document.querySelector('select[name="sortOrder"]');
    if (orderSelect) {
        orderSelect.addEventListener('change', function() {
            filterState.sortOrder = this.value;
            applyFiltersWithURL();
        });
    }
    
    // Sortable column headers
    const sortableHeaders = document.querySelectorAll('.sortable-header');
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const column = this.dataset.sort;
            if (filterState.sortBy === column) {
                // Toggle order
                filterState.sortOrder = filterState.sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                filterState.sortBy = column;
                filterState.sortOrder = 'desc';
            }
            applyFiltersWithURL();
        });
    });
}

/**
 * Set up advanced filters
 */
function setupAdvancedFilters() {
    // Date range filter
    const dateRangeSelect = document.querySelector('select[name="dateRange"]');
    if (dateRangeSelect) {
        dateRangeSelect.addEventListener('change', function() {
            filterState.dateRange = this.value;
            filterState.page = 1;
            applyFiltersWithURL();
        });
    }
    
    // Tag filters
    setupTagFilters();
    
    // Custom date picker
    setupCustomDatePicker();
}

/**
 * Set up tag filtering
 */
function setupTagFilters() {
    const tagInputs = document.querySelectorAll('input[name="tags"]');
    tagInputs.forEach(input => {
        input.addEventListener('change', function() {
            const tag = this.value;
            if (this.checked) {
                if (!filterState.tags.includes(tag)) {
                    filterState.tags.push(tag);
                }
            } else {
                filterState.tags = filterState.tags.filter(t => t !== tag);
            }
            filterState.page = 1;
            applyFiltersWithURL();
        });
    });
}

/**
 * Set up custom date picker
 */
function setupCustomDatePicker() {
    const startDateInput = document.querySelector('input[name="startDate"]');
    const endDateInput = document.querySelector('input[name="endDate"]');
    
    if (startDateInput && endDateInput) {
        [startDateInput, endDateInput].forEach(input => {
            input.addEventListener('change', function() {
                if (startDateInput.value && endDateInput.value) {
                    filterState.dateRange = `custom:${startDateInput.value}:${endDateInput.value}`;
                    filterState.page = 1;
                    applyFiltersWithURL();
                }
            });
        });
    }
}

/**
 * Apply filters and update URL
 */
function applyFiltersWithURL() {
    // Update URL
    updateURL();
    
    // Apply filters
    applyFilters();
    
    // Save to history
    saveFilterHistory();
}

/**
 * Apply current filters to visible content
 */
function applyFilters() {
    // Show loading state
    showFilterLoading();
    
    // Get all filterable items
    const items = document.querySelectorAll('.threat-item, .actor-item, .tool-item');
    let visibleCount = 0;
    
    items.forEach(item => {
        if (itemMatchesFilters(item)) {
            item.style.display = 'block';
            item.classList.add('fade-in');
            visibleCount++;
        } else {
            item.style.display = 'none';
            item.classList.remove('fade-in');
        }
    });
    
    // Sort visible items
    sortVisibleItems();
    
    // Update results count
    updateResultsCount(visibleCount);
    
    // Hide loading state
    hideFilterLoading();
    
    // Update pagination if needed
    updatePagination(visibleCount);
}

/**
 * Check if item matches current filters
 */
function itemMatchesFilters(item) {
    // Search filter
    if (filterState.search) {
        const searchText = getItemSearchText(item).toLowerCase();
        const searchTerms = filterState.search.toLowerCase().split(' ');
        const matches = searchTerms.every(term => searchText.includes(term));
        if (!matches) return false;
    }
    
    // Severity filter
    if (filterState.severity) {
        const itemSeverity = getItemAttribute(item, 'severity');
        if (itemSeverity !== filterState.severity) return false;
    }
    
    // Source filter
    if (filterState.source) {
        const itemSource = getItemAttribute(item, 'source');
        if (itemSource !== filterState.source) return false;
    }
    
    // Tactic filter
    if (filterState.tactic) {
        const itemTactic = getItemAttribute(item, 'tactic');
        if (itemTactic !== filterState.tactic) return false;
    }
    
    // Tags filter
    if (filterState.tags.length > 0) {
        const itemTags = getItemTags(item);
        const hasMatchingTag = filterState.tags.some(tag => itemTags.includes(tag));
        if (!hasMatchingTag) return false;
    }
    
    // Date range filter
    if (filterState.dateRange) {
        if (!itemMatchesDateRange(item, filterState.dateRange)) return false;
    }
    
    return true;
}

/**
 * Get searchable text from item
 */
function getItemSearchText(item) {
    const title = item.querySelector('.threat-title, .actor-name, .tool-name')?.textContent || '';
    const description = item.querySelector('.threat-description, .actor-description, .tool-description')?.textContent || '';
    const tags = getItemTags(item).join(' ');
    
    return `${title} ${description} ${tags}`;
}

/**
 * Get attribute value from item
 */
function getItemAttribute(item, attribute) {
    return item.dataset[attribute] || 
           item.querySelector(`[data-${attribute}]`)?.dataset[attribute] || 
           '';
}

/**
 * Get tags from item
 */
function getItemTags(item) {
    const tagElements = item.querySelectorAll('.badge, .tag');
    return Array.from(tagElements).map(el => el.textContent.trim().toLowerCase());
}

/**
 * Check if item matches date range
 */
function itemMatchesDateRange(item, dateRange) {
    const itemDate = getItemAttribute(item, 'date');
    if (!itemDate) return true;
    
    const itemDateTime = new Date(itemDate);
    const now = new Date();
    
    switch (dateRange) {
        case 'today':
            return isSameDay(itemDateTime, now);
        case 'week':
            return isWithinDays(itemDateTime, now, 7);
        case 'month':
            return isWithinDays(itemDateTime, now, 30);
        case 'quarter':
            return isWithinDays(itemDateTime, now, 90);
        default:
            if (dateRange.startsWith('custom:')) {
                const [, startDate, endDate] = dateRange.split(':');
                const start = new Date(startDate);
                const end = new Date(endDate);
                return itemDateTime >= start && itemDateTime <= end;
            }
            return true;
    }
}

/**
 * Check if two dates are the same day
 */
function isSameDay(date1, date2) {
    return date1.toDateString() === date2.toDateString();
}

/**
 * Check if date is within specified days
 */
function isWithinDays(date, referenceDate, days) {
    const diffTime = referenceDate - date;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays >= 0 && diffDays <= days;
}

/**
 * Sort visible items
 */
function sortVisibleItems() {
    const container = document.querySelector('.threat-list, .actor-list, .tool-list');
    if (!container) return;
    
    const items = Array.from(container.querySelectorAll('[style*="display: block"], [style=""]'));
    
    items.sort((a, b) => {
        const aValue = getSortValue(a, filterState.sortBy);
        const bValue = getSortValue(b, filterState.sortBy);
        
        let comparison = 0;
        if (aValue < bValue) comparison = -1;
        if (aValue > bValue) comparison = 1;
        
        return filterState.sortOrder === 'desc' ? -comparison : comparison;
    });
    
    // Reorder DOM elements
    items.forEach(item => container.appendChild(item));
}

/**
 * Get sort value for item
 */
function getSortValue(item, sortBy) {
    switch (sortBy) {
        case 'name':
            return item.querySelector('.threat-title, .actor-name, .tool-name')?.textContent || '';
        case 'severity':
            const severity = getItemAttribute(item, 'severity');
            const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0 };
            return severityOrder[severity] || 0;
        case 'source':
            return getItemAttribute(item, 'source');
        case 'date':
        default:
            const dateStr = getItemAttribute(item, 'date');
            return dateStr ? new Date(dateStr) : new Date(0);
    }
}

/**
 * Update URL with current filter state
 */
function updateURL() {
    const url = new URL(window.location);
    
    // Clear existing parameters
    url.search = '';
    
    // Add non-empty filter parameters
    Object.entries(filterState).forEach(([key, value]) => {
        if (value && (typeof value !== 'object' || value.length > 0)) {
            if (Array.isArray(value)) {
                url.searchParams.set(key, value.join(','));
            } else {
                url.searchParams.set(key, value);
            }
        }
    });
    
    // Update URL without page reload
    window.history.replaceState({}, '', url);
}

/**
 * Clear all filters
 */
function clearAllFilters() {
    filterState = {
        search: '',
        severity: '',
        source: '',
        tactic: '',
        tags: [],
        dateRange: '',
        sortBy: 'date',
        sortOrder: 'desc',
        page: 1
    };
    
    updateFormControlsFromState();
    applyFiltersWithURL();
    
    showAlert('All filters cleared', 'info', 2000);
}

/**
 * Toggle advanced filters visibility
 */
function toggleAdvancedFilters() {
    const advancedPanel = document.querySelector('.advanced-filters');
    const toggleButton = document.querySelector('.advanced-filters-toggle');
    
    if (advancedPanel && toggleButton) {
        const isVisible = advancedPanel.style.display !== 'none';
        
        if (isVisible) {
            advancedPanel.style.display = 'none';
            toggleButton.innerHTML = '<i class="fas fa-chevron-down me-1"></i>Show Advanced Filters';
        } else {
            advancedPanel.style.display = 'block';
            toggleButton.innerHTML = '<i class="fas fa-chevron-up me-1"></i>Hide Advanced Filters';
        }
    }
}

/**
 * Show filter loading state
 */
function showFilterLoading() {
    const loadingIndicator = document.querySelector('.filter-loading');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    }
    
    // Add loading class to items container
    const container = document.querySelector('.threat-list, .actor-list, .tool-list');
    if (container) {
        container.classList.add('filtering');
    }
}

/**
 * Hide filter loading state
 */
function hideFilterLoading() {
    const loadingIndicator = document.querySelector('.filter-loading');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
    
    // Remove loading class from items container
    const container = document.querySelector('.threat-list, .actor-list, .tool-list');
    if (container) {
        container.classList.remove('filtering');
    }
}

/**
 * Update results count display
 */
function updateResultsCount(count) {
    const countElement = document.querySelector('.results-count');
    if (countElement) {
        const total = document.querySelectorAll('.threat-item, .actor-item, .tool-item').length;
        countElement.textContent = `Showing ${count} of ${total} items`;
    }
    
    // Show/hide no results message
    const noResultsMessage = document.querySelector('.no-results-message');
    if (count === 0) {
        if (!noResultsMessage) {
            createNoResultsMessage();
        }
    } else {
        if (noResultsMessage) {
            noResultsMessage.remove();
        }
    }
}

/**
 * Create no results message
 */
function createNoResultsMessage() {
    const container = document.querySelector('.threat-list, .actor-list, .tool-list');
    if (!container) return;
    
    const message = document.createElement('div');
    message.className = 'no-results-message text-center py-5';
    message.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-search fa-3x text-muted mb-3"></i>
            <h4>No results found</h4>
            <p class="text-muted mb-3">Try adjusting your search criteria or filters</p>
            <button class="btn btn-outline-primary" onclick="clearAllFilters()">
                <i class="fas fa-times me-1"></i>Clear All Filters
            </button>
        </div>
    `;
    
    container.appendChild(message);
}

/**
 * Update pagination based on filtered results
 */
function updatePagination(totalItems) {
    const pagination = document.querySelector('.pagination');
    if (!pagination) return;
    
    const itemsPerPage = 20; // Should match backend setting
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    
    if (totalPages <= 1) {
        pagination.style.display = 'none';
        return;
    }
    
    pagination.style.display = 'flex';
    
    // Update pagination links
    const pageLinks = pagination.querySelectorAll('.page-link');
    pageLinks.forEach(link => {
        const href = new URL(link.href);
        
        // Update URL parameters for each page link
        Object.entries(filterState).forEach(([key, value]) => {
            if (value && (typeof value !== 'object' || value.length > 0)) {
                if (Array.isArray(value)) {
                    href.searchParams.set(key, value.join(','));
                } else if (key !== 'page') {
                    href.searchParams.set(key, value);
                }
            }
        });
        
        link.href = href.toString();
    });
}

/**
 * Save current filter state to history
 */
function saveFilterHistory() {
    const historyEntry = {
        timestamp: Date.now(),
        filters: { ...filterState },
        url: window.location.href
    };
    
    filterHistory.unshift(historyEntry);
    
    // Keep only last 10 entries
    if (filterHistory.length > 10) {
        filterHistory = filterHistory.slice(0, 10);
    }
    
    // Save to sessionStorage
    try {
        sessionStorage.setItem('filterHistory', JSON.stringify(filterHistory));
    } catch (error) {
        console.warn('Could not save filter history:', error);
    }
}

/**
 * Load filter history from sessionStorage
 */
function loadFilterHistory() {
    try {
        const saved = sessionStorage.getItem('filterHistory');
        if (saved) {
            filterHistory = JSON.parse(saved);
        }
    } catch (error) {
        console.warn('Could not load filter history:', error);
        filterHistory = [];
    }
}

/**
 * Show filter history dropdown
 */
function showFilterHistory() {
    if (filterHistory.length === 0) {
        showAlert('No filter history available', 'info', 2000);
        return;
    }
    
    const dropdown = createFilterHistoryDropdown();
    document.body.appendChild(dropdown);
    
    // Position dropdown
    const button = document.querySelector('.filter-history-btn');
    if (button) {
        const rect = button.getBoundingClientRect();
        dropdown.style.position = 'absolute';
        dropdown.style.top = (rect.bottom + 5) + 'px';
        dropdown.style.left = rect.left + 'px';
        dropdown.style.zIndex = '1000';
    }
    
    // Show dropdown
    dropdown.style.display = 'block';
    
    // Hide on click outside
    setTimeout(() => {
        document.addEventListener('click', function hideHistory(e) {
            if (!dropdown.contains(e.target)) {
                dropdown.remove();
                document.removeEventListener('click', hideHistory);
            }
        });
    }, 100);
}

/**
 * Create filter history dropdown
 */
function createFilterHistoryDropdown() {
    const dropdown = document.createElement('div');
    dropdown.className = 'filter-history-dropdown bg-white border rounded shadow-lg p-2';
    dropdown.style.minWidth = '300px';
    dropdown.style.maxHeight = '400px';
    dropdown.style.overflowY = 'auto';
    
    dropdown.innerHTML = `
        <div class="dropdown-header">
            <h6 class="mb-2">Recent Filters</h6>
        </div>
        ${filterHistory.map((entry, index) => `
            <div class="filter-history-item p-2 border-bottom cursor-pointer" data-index="${index}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <small class="text-muted">${new Date(entry.timestamp).toLocaleString()}</small>
                        <div class="mt-1">
                            ${formatFilterSummary(entry.filters)}
                        </div>
                    </div>
                    <button class="btn btn-sm btn-outline-primary ms-2" onclick="applyHistoryFilter(${index})">
                        Apply
                    </button>
                </div>
            </div>
        `).join('')}
        <div class="dropdown-footer pt-2">
            <button class="btn btn-sm btn-outline-secondary w-100" onclick="clearFilterHistory()">
                Clear History
            </button>
        </div>
    `;
    
    return dropdown;
}

/**
 * Format filter summary for display
 */
function formatFilterSummary(filters) {
    const parts = [];
    
    if (filters.search) parts.push(`Search: "${filters.search}"`);
    if (filters.severity) parts.push(`Severity: ${filters.severity}`);
    if (filters.source) parts.push(`Source: ${filters.source}`);
    if (filters.tactic) parts.push(`Tactic: ${filters.tactic}`);
    if (filters.tags.length > 0) parts.push(`Tags: ${filters.tags.join(', ')}`);
    if (filters.dateRange) parts.push(`Date: ${filters.dateRange}`);
    
    return parts.length > 0 ? parts.join(' | ') : 'No filters';
}

/**
 * Apply filter from history
 */
function applyHistoryFilter(index) {
    if (filterHistory[index]) {
        filterState = { ...filterHistory[index].filters };
        updateFormControlsFromState();
        applyFiltersWithURL();
        
        // Remove dropdown
        const dropdown = document.querySelector('.filter-history-dropdown');
        if (dropdown) {
            dropdown.remove();
        }
        
        showAlert('Filter applied from history', 'success', 2000);
    }
}

/**
 * Clear filter history
 */
function clearFilterHistory() {
    filterHistory = [];
    
    try {
        sessionStorage.removeItem('filterHistory');
    } catch (error) {
        console.warn('Could not clear filter history:', error);
    }
    
    // Remove dropdown
    const dropdown = document.querySelector('.filter-history-dropdown');
    if (dropdown) {
        dropdown.remove();
    }
    
    showAlert('Filter history cleared', 'info', 2000);
}

/**
 * Export filtered results
 */
function exportFilteredResults() {
    const visibleItems = document.querySelectorAll('.threat-item[style*="display: block"], .actor-item[style*="display: block"], .tool-item[style*="display: block"]');
    
    if (visibleItems.length === 0) {
        showAlert('No items to export', 'warning');
        return;
    }
    
    const data = {
        filters: filterState,
        exportTime: new Date().toISOString(),
        totalItems: visibleItems.length,
        items: Array.from(visibleItems).map(item => extractItemData(item))
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `filtered-threats-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAlert(`Exported ${visibleItems.length} items`, 'success');
}

/**
 * Extract data from item element
 */
function extractItemData(item) {
    return {
        id: getItemAttribute(item, 'id'),
        name: item.querySelector('.threat-title, .actor-name, .tool-name')?.textContent || '',
        description: item.querySelector('.threat-description, .actor-description, .tool-description')?.textContent || '',
        severity: getItemAttribute(item, 'severity'),
        source: getItemAttribute(item, 'source'),
        tactic: getItemAttribute(item, 'tactic'),
        date: getItemAttribute(item, 'date'),
        tags: getItemTags(item)
    };
}

/**
 * Initialize filter presets
 */
function initializeFilterPresets() {
    const presets = {
        'critical-threats': {
            name: 'Critical Threats',
            filters: { severity: 'Critical', sortBy: 'date', sortOrder: 'desc' }
        },
        'recent-activity': {
            name: 'Recent Activity', 
            filters: { dateRange: 'week', sortBy: 'date', sortOrder: 'desc' }
        },
        'apt-groups': {
            name: 'APT Groups',
            filters: { tags: ['apt'], sortBy: 'name', sortOrder: 'asc' }
        },
        'mitre-techniques': {
            name: 'MITRE Techniques',
            filters: { source: 'MITRE ATT&CK', sortBy: 'tactic', sortOrder: 'asc' }
        }
    };
    
    // Create preset buttons
    const presetContainer = document.querySelector('.filter-presets');
    if (presetContainer) {
        Object.entries(presets).forEach(([key, preset]) => {
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-secondary me-2 mb-2';
            button.textContent = preset.name;
            button.onclick = () => applyFilterPreset(preset.filters);
            presetContainer.appendChild(button);
        });
    }
}

/**
 * Apply filter preset
 */
function applyFilterPreset(presetFilters) {
    filterState = { ...filterState, ...presetFilters, page: 1 };
    updateFormControlsFromState();
    applyFiltersWithURL();
    
    showAlert(`Applied filter preset`, 'info', 2000);
}

// Load filter history on initialization
loadFilterHistory();

// Initialize filter presets
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(initializeFilterPresets, 100);
});

// Make functions available globally
window.clearAllFilters = clearAllFilters;
window.applyHistoryFilter = applyHistoryFilter;
window.clearFilterHistory = clearFilterHistory;
window.exportFilteredResults = exportFilteredResults;
window.showFilterHistory = showFilterHistory;

// Export filter functionality
window.Filters = {
    applyFilters,
    clearAllFilters,
    updateResultsCount,
    exportFilteredResults,
    filterState
};