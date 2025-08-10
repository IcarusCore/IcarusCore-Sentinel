/**
 * Main JavaScript for Threat Intel Dashboard
 * Handles global functionality, alerts, and API interactions
 */

// Global variables
let isRefreshing = false;
let lastUpdateTime = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    updateLastUpdateTime();
    
    // Auto-refresh every 30 minutes
    setInterval(checkForUpdates, 30 * 60 * 1000);
});

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('Threat Intel Dashboard initialized');
    
    // Initialize tooltips
    initializeTooltips();
    
    // Check for stored preferences
    loadUserPreferences();
    
    // Set up responsive navigation
    setupResponsiveNav();
}

/**
 * Set up global event listeners
 */
function setupEventListeners() {
    // Refresh button
    const refreshBtn = document.querySelector('[onclick="refreshData()"]');
    if (refreshBtn) {
        refreshBtn.removeAttribute('onclick');
        refreshBtn.addEventListener('click', refreshData);
    }
    
    // Search forms
    const searchForms = document.querySelectorAll('.search-form');
    searchForms.forEach(form => {
        form.addEventListener('submit', handleSearch);
    });
    
    // Filter dropdowns
    const filterSelects = document.querySelectorAll('.filter-select');
    filterSelects.forEach(select => {
        select.addEventListener('change', handleFilterChange);
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
    
    // Window resize handler
    window.addEventListener('resize', debounce(handleWindowResize, 250));
}

/**
 * Refresh threat intelligence data
 */
async function refreshData() {
    if (isRefreshing) {
        showAlert('Data refresh already in progress...', 'info');
        return;
    }
    
    isRefreshing = true;
    
    try {
        // Show loading indicator
        showRefreshIndicator();
        
        // Update button state
        const refreshBtn = document.querySelector('.btn[onclick*="refreshData"], .btn-outline-light');
        if (refreshBtn) {
            const originalContent = refreshBtn.innerHTML;
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Refreshing...';
            refreshBtn.disabled = true;
            
            // Restore button after operation
            setTimeout(() => {
                refreshBtn.innerHTML = originalContent;
                refreshBtn.disabled = false;
            }, 5000);
        }
        
        // Call refresh API
        const response = await fetch('/api/refresh');
        const result = await response.json();
        
        if (result.status === 'success') {
            showAlert('Threat data refreshed successfully!', 'success');
            
            // Reload current page after short delay
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            throw new Error(result.message || 'Refresh failed');
        }
        
    } catch (error) {
        console.error('Error refreshing data:', error);
        showAlert('Failed to refresh data: ' + error.message, 'danger');
    } finally {
        isRefreshing = false;
        hideRefreshIndicator();
    }
}

/**
 * Show alert message to user
 */
function showAlert(message, type = 'info', duration = 5000) {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;
    
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('beforeend', alertHtml);
    
    // Auto-dismiss after duration
    if (duration > 0) {
        setTimeout(() => {
            const alert = document.getElementById(alertId);
            if (alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, duration);
    }
}

/**
 * Get appropriate icon for alert type
 */
function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Show refresh indicator
 */
function showRefreshIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'refreshIndicator';
    indicator.className = 'refresh-indicator';
    indicator.innerHTML = '<i class="fas fa-sync-alt fa-spin me-2"></i>Updating threat data...';
    
    document.body.appendChild(indicator);
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
        hideRefreshIndicator();
    }, 10000);
}

/**
 * Hide refresh indicator
 */
function hideRefreshIndicator() {
    const indicator = document.getElementById('refreshIndicator');
    if (indicator) {
        indicator.classList.add('fade-out');
        setTimeout(() => {
            indicator.remove();
        }, 300);
    }
}

/**
 * Handle search form submissions
 */
function handleSearch(event) {
    event.preventDefault();
    
    const form = event.target;
    const searchInput = form.querySelector('input[name="search"]');
    const searchTerm = searchInput.value.trim();
    
    if (!searchTerm) {
        showAlert('Please enter a search term', 'warning');
        return;
    }
    
    // Update URL with search parameter
    const url = new URL(window.location);
    url.searchParams.set('search', searchTerm);
    url.searchParams.set('page', '1'); // Reset to first page
    
    window.location.href = url.toString();
}

/**
 * Handle filter dropdown changes
 */
function handleFilterChange(event) {
    const select = event.target;
    const filterName = select.name;
    const filterValue = select.value;
    
    // Update URL with filter parameter
    const url = new URL(window.location);
    
    if (filterValue) {
        url.searchParams.set(filterName, filterValue);
    } else {
        url.searchParams.delete(filterName);
    }
    
    url.searchParams.set('page', '1'); // Reset to first page
    window.location.href = url.toString();
}

/**
 * Handle keyboard shortcuts
 */
function handleKeyboardShortcuts(event) {
    // Ctrl/Cmd + R: Refresh data
    if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
        event.preventDefault();
        refreshData();
        return;
    }
    
    // Ctrl/Cmd + F: Focus search
    if ((event.ctrlKey || event.metaKey) && event.key === 'f') {
        const searchInput = document.querySelector('input[name="search"]');
        if (searchInput) {
            event.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
    }
    
    // Escape: Clear search
    if (event.key === 'Escape') {
        const searchInput = document.querySelector('input[name="search"]');
        if (searchInput && searchInput === document.activeElement) {
            searchInput.value = '';
        }
    }
}

/**
 * Handle window resize
 */
function handleWindowResize() {
    // Adjust layout for mobile
    adjustMobileLayout();
    
    // Recalculate card heights if needed
    equalizeCardHeights();
}

/**
 * Initialize tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Load user preferences from localStorage
 */
function loadUserPreferences() {
    try {
        const preferences = localStorage.getItem('threatDashboardPrefs');
        if (preferences) {
            const prefs = JSON.parse(preferences);
            
            // Apply theme preference
            if (prefs.theme) {
                document.body.classList.toggle('dark-theme', prefs.theme === 'dark');
            }
            
            // Apply other preferences
            if (prefs.autoRefresh !== undefined) {
                setAutoRefresh(prefs.autoRefresh);
            }
        }
    } catch (error) {
        console.warn('Error loading user preferences:', error);
    }
}

/**
 * Save user preferences to localStorage
 */
function saveUserPreferences(preferences) {
    try {
        const existing = JSON.parse(localStorage.getItem('threatDashboardPrefs') || '{}');
        const updated = { ...existing, ...preferences };
        localStorage.setItem('threatDashboardPrefs', JSON.stringify(updated));
    } catch (error) {
        console.warn('Error saving user preferences:', error);
    }
}

/**
 * Set up responsive navigation
 */
function setupResponsiveNav() {
    const navbar = document.querySelector('.navbar');
    const navbarToggler = document.querySelector('.navbar-toggler');
    
    if (navbarToggler) {
        navbarToggler.addEventListener('click', function() {
            setTimeout(() => {
                adjustMobileLayout();
            }, 300);
        });
    }
}

/**
 * Adjust layout for mobile devices
 */
function adjustMobileLayout() {
    const isMobile = window.innerWidth < 768;
    const cards = document.querySelectorAll('.card');
    
    cards.forEach(card => {
        if (isMobile) {
            card.classList.add('mobile-card');
        } else {
            card.classList.remove('mobile-card');
        }
    });
}

/**
 * Equalize card heights in a row
 */
function equalizeCardHeights() {
    const cardRows = document.querySelectorAll('.row');
    
    cardRows.forEach(row => {
        const cards = row.querySelectorAll('.card');
        if (cards.length > 1) {
            // Reset heights
            cards.forEach(card => {
                card.style.height = 'auto';
            });
            
            // Find max height
            let maxHeight = 0;
            cards.forEach(card => {
                maxHeight = Math.max(maxHeight, card.offsetHeight);
            });
            
            // Apply max height
            cards.forEach(card => {
                card.style.height = maxHeight + 'px';
            });
        }
    });
}

/**
 * Check for updates via API
 */
async function checkForUpdates() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        if (stats.last_updated && lastUpdateTime && stats.last_updated !== lastUpdateTime) {
            showAlert('New threat intelligence data is available!', 'info');
        }
        
        lastUpdateTime = stats.last_updated;
    } catch (error) {
        console.warn('Error checking for updates:', error);
    }
}

/**
 * Update last update time display
 */
function updateLastUpdateTime() {
    const lastUpdatedElement = document.getElementById('lastUpdated');
    if (lastUpdatedElement) {
        const now = new Date();
        lastUpdatedElement.textContent = now.toLocaleString();
    }
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (error) {
        return dateString;
    }
}

/**
 * Truncate text to specified length
 */
function truncateText(text, maxLength = 150) {
    if (!text || text.length <= maxLength) {
        return text;
    }
    return text.substring(0, maxLength - 3) + '...';
}

/**
 * Debounce function to limit function calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('Copied to clipboard!', 'success', 2000);
    } catch (error) {
        console.warn('Failed to copy to clipboard:', error);
        showAlert('Failed to copy to clipboard', 'warning');
    }
}

/**
 * Open external link safely with validation
 */
function openExternalLink(url) {
    if (!url) {
        console.warn('No URL provided to openExternalLink');
        return;
    }
    
    // Validate URL format
    try {
        const urlObj = new URL(url);
        if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
            console.warn('Invalid URL protocol:', url);
            return;
        }
    } catch (error) {
        console.warn('Invalid URL format:', url);
        return;
    }
    
    window.open(url, '_blank', 'noopener,noreferrer');
}

/**
 * Open MITRE ATT&CK technique link with correct formatting
 */
function openMitreLink(techniqueId) {
    if (!techniqueId || !techniqueId.startsWith('T')) {
        console.warn('Invalid MITRE technique ID:', techniqueId);
        return;
    }
    
    let url;
    if (techniqueId.includes('.')) {
        // Sub-technique: T1546.012 -> T1546/012
        const [main, sub] = techniqueId.split('.');
        url = `https://attack.mitre.org/techniques/${main}/${sub}/`;
    } else {
        // Main technique: T1546 -> T1546
        url = `https://attack.mitre.org/techniques/${techniqueId}/`;
    }
    
    openExternalLink(url);
}

/**
 * Scroll to top of page
 */
function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

/**
 * Set auto-refresh interval
 */
function setAutoRefresh(enabled) {
    if (enabled) {
        // Enable auto-refresh every 30 minutes
        if (!window.autoRefreshInterval) {
            window.autoRefreshInterval = setInterval(refreshData, 30 * 60 * 1000);
        }
    } else {
        // Disable auto-refresh
        if (window.autoRefreshInterval) {
            clearInterval(window.autoRefreshInterval);
            window.autoRefreshInterval = null;
        }
    }
    
    saveUserPreferences({ autoRefresh: enabled });
}

// Export functions for use in other modules
window.ThreatDashboard = {
    refreshData,
    showAlert,
    formatDate,
    truncateText,
    copyToClipboard,
    openExternalLink,
    openMitreLink,
    scrollToTop,
    setAutoRefresh
};