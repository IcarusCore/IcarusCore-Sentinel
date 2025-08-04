/**
 * Dashboard-specific JavaScript functionality
 * Handles dashboard widgets, charts, and interactive elements
 */

// Dashboard state
let dashboardData = {
    stats: {},
    threats: [],
    actors: [],
    tools: []
};

let updateInterval;
let chartInstances = {};

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (isDashboardPage()) {
        initializeDashboard();
    }
});

/**
 * Check if current page is dashboard
 */
function isDashboardPage() {
    return window.location.pathname === '/' || 
           document.querySelector('.dashboard-hero') !== null;
}

/**
 * Initialize dashboard functionality
 */
function initializeDashboard() {
    console.log('Initializing dashboard...');
    
    // Load initial data
    loadDashboardData();
    
    // Set up real-time updates
    setupRealTimeUpdates();
    
    // Initialize interactive elements
    initializeDashboardElements();
    
    // Set up keyboard shortcuts
    setupDashboardShortcuts();
    
    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
}

/**
 * Load dashboard data from API
 */
async function loadDashboardData() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            dashboardData.stats = await response.json();
            updateStatsDisplay();
        }
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showAlert('Failed to load dashboard data', 'warning');
    }
}

/**
 * Update statistics display
 */
function updateStatsDisplay() {
    const stats = dashboardData.stats;
    
    // Update stat numbers with animation
    updateStatWithAnimation('total_threats', stats.total_threats);
    updateStatWithAnimation('total_actors', stats.total_actors); 
    updateStatWithAnimation('total_tools', stats.total_tools);
    
    // Update last updated time
    const lastUpdatedElement = document.getElementById('lastUpdated');
    if (lastUpdatedElement && stats.last_updated) {
        lastUpdatedElement.textContent = formatDate(stats.last_updated);
    }
    
    // Update progress indicators if present
    updateProgressIndicators(stats);
}

/**
 * Update a stat number with animation
 */
function updateStatWithAnimation(elementId, newValue) {
    const element = document.querySelector(`[data-stat="${elementId}"]`) || 
                   document.getElementById(elementId);
    
    if (!element) return;
    
    const currentValue = parseInt(element.textContent) || 0;
    const targetValue = newValue || 0;
    
    if (currentValue === targetValue) return;
    
    // Animate the number change
    const duration = 1000; // 1 second
    const startTime = Date.now();
    const difference = targetValue - currentValue;
    
    const updateNumber = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function (ease-out)
        const easedProgress = 1 - Math.pow(1 - progress, 3);
        const currentNum = Math.round(currentValue + (difference * easedProgress));
        
        element.textContent = currentNum.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame(updateNumber);
        }
    };
    
    requestAnimationFrame(updateNumber);
}

/**
 * Update progress indicators
 */
function updateProgressIndicators(stats) {
    // Critical threats progress
    const criticalProgress = document.querySelector('.critical-progress');
    if (criticalProgress && stats.critical_threats !== undefined) {
        const percentage = stats.total_threats > 0 ? 
            (stats.critical_threats / stats.total_threats) * 100 : 0;
        criticalProgress.style.width = percentage + '%';
        criticalProgress.setAttribute('aria-valuenow', percentage);
    }
    
    // High threats progress
    const highProgress = document.querySelector('.high-progress');
    if (highProgress && stats.high_threats !== undefined) {
        const percentage = stats.total_threats > 0 ? 
            (stats.high_threats / stats.total_threats) * 100 : 0;
        highProgress.style.width = percentage + '%';
        highProgress.setAttribute('aria-valuenow', percentage);
    }
}

/**
 * Set up real-time updates
 */
function setupRealTimeUpdates() {
    // Update every 5 minutes
    updateInterval = setInterval(() => {
        loadDashboardData();
    }, 5 * 60 * 1000);
    
    // Clean up on page unload
    window.addEventListener('beforeunload', () => {
        if (updateInterval) {
            clearInterval(updateInterval);
        }
    });
}

/**
 * Initialize dashboard interactive elements
 */
function initializeDashboardElements() {
    // Stat cards hover effects
    initializeStatCards();
    
    // Threat items interactions
    initializeThreatItems();
    
    // Quick action buttons
    initializeQuickActions();
    
    // Search functionality
    initializeDashboardSearch();
}

/**
 * Initialize stat cards with hover effects
 */
function initializeStatCards() {
    const statCards = document.querySelectorAll('.stat-card');
    
    statCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
        
        // Make cards clickable
        card.addEventListener('click', function() {
            const cardType = this.classList.contains('stat-threats') ? 'ttps' :
                           this.classList.contains('stat-actors') ? 'actors' :
                           this.classList.contains('stat-tools') ? 'tools' : null;
            
            if (cardType) {
                window.location.href = `/${cardType}`;
            }
        });
        
        // Add cursor pointer
        card.style.cursor = 'pointer';
    });
}

/**
 * Initialize threat items with interactions
 */
function initializeThreatItems() {
    const threatItems = document.querySelectorAll('.threat-item');
    
    threatItems.forEach(item => {
        // Add click handler to expand/collapse
        const header = item.querySelector('.threat-header');
        if (header) {
            header.addEventListener('click', function() {
                toggleThreatDetails(item);
            });
        }
        
        // Add copy functionality for threat IDs
        const threatId = item.querySelector('.threat-id');
        if (threatId) {
            threatId.addEventListener('click', function(e) {
                e.stopPropagation();
                copyToClipboard(this.textContent);
            });
            threatId.style.cursor = 'pointer';
            threatId.title = 'Click to copy ID';
        }
        
        // Add external link handlers
        const externalLinks = item.querySelectorAll('a[href^="http"]');
        externalLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                openExternalLink(this.href);
            });
        });
    });
}

/**
 * Toggle threat item details
 */
function toggleThreatDetails(threatItem) {
    const details = threatItem.querySelector('.threat-details');
    if (!details) return;
    
    const isExpanded = details.style.display !== 'none';
    
    if (isExpanded) {
        // Collapse
        details.style.display = 'none';
        threatItem.classList.remove('expanded');
    } else {
        // Expand
        details.style.display = 'block';
        threatItem.classList.add('expanded');
        
        // Scroll into view if needed
        setTimeout(() => {
            if (threatItem.getBoundingClientRect().bottom > window.innerHeight) {
                threatItem.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'nearest' 
                });
            }
        }, 100);
    }
}

/**
 * Initialize quick action buttons
 */
function initializeQuickActions() {
    const actionButtons = document.querySelectorAll('.action-btn');
    
    actionButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const action = this.dataset.action;
            
            switch (action) {
                case 'refresh':
                    e.preventDefault();
                    refreshData();
                    break;
                case 'export':
                    e.preventDefault();
                    exportDashboardData();
                    break;
                case 'settings':
                    e.preventDefault();
                    openSettingsModal();
                    break;
            }
        });
    });
}

/**
 * Initialize dashboard search
 */
function initializeDashboardSearch() {
    const searchInput = document.querySelector('.dashboard-search');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length === 0) {
            showAllThreatItems();
            return;
        }
        
        // Debounce search
        searchTimeout = setTimeout(() => {
            filterThreatItems(query);
        }, 300);
    });
    
    // Clear search on escape
    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            this.value = '';
            showAllThreatItems();
        }
    });
}

/**
 * Filter threat items based on search query
 */
function filterThreatItems(query) {
    const threatItems = document.querySelectorAll('.threat-item');
    const queryLower = query.toLowerCase();
    let visibleCount = 0;
    
    threatItems.forEach(item => {
        const title = item.querySelector('.threat-title')?.textContent.toLowerCase() || '';
        const description = item.querySelector('.threat-description')?.textContent.toLowerCase() || '';
        const tags = Array.from(item.querySelectorAll('.badge'))
            .map(badge => badge.textContent.toLowerCase()).join(' ');
        
        const matches = title.includes(queryLower) || 
                       description.includes(queryLower) || 
                       tags.includes(queryLower);
        
        if (matches) {
            item.style.display = 'block';
            visibleCount++;
        } else {
            item.style.display = 'none';
        }
    });
    
    // Show no results message if needed
    showSearchResults(visibleCount, query);
}

/**
 * Show all threat items
 */
function showAllThreatItems() {
    const threatItems = document.querySelectorAll('.threat-item');
    threatItems.forEach(item => {
        item.style.display = 'block';
    });
    
    // Hide no results message
    const noResults = document.querySelector('.no-search-results');
    if (noResults) {
        noResults.remove();
    }
}

/**
 * Show search results info
 */
function showSearchResults(count, query) {
    // Remove existing no results message
    const existingNoResults = document.querySelector('.no-search-results');
    if (existingNoResults) {
        existingNoResults.remove();
    }
    
    if (count === 0) {
        const threatContainer = document.querySelector('.recent-threats, .threat-list');
        if (threatContainer) {
            const noResults = document.createElement('div');
            noResults.className = 'no-search-results text-center py-4';
            noResults.innerHTML = `
                <i class="fas fa-search fa-2x text-muted mb-3"></i>
                <h5>No threats found</h5>
                <p class="text-muted">No threats match your search for "${query}"</p>
                <button class="btn btn-outline-primary" onclick="document.querySelector('.dashboard-search').value=''; showAllThreatItems();">
                    Clear Search
                </button>
            `;
            threatContainer.appendChild(noResults);
        }
    }
}

/**
 * Export dashboard data
 */
function exportDashboardData() {
    const data = {
        stats: dashboardData.stats,
        exportTime: new Date().toISOString(),
        threats: dashboardData.threats,
        actors: dashboardData.actors,
        tools: dashboardData.tools
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-intel-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAlert('Dashboard data exported successfully!', 'success');
}

/**
 * Open settings modal
 */
function openSettingsModal() {
    // Create modal if it doesn't exist
    let modal = document.getElementById('settingsModal');
    if (!modal) {
        modal = createSettingsModal();
        document.body.appendChild(modal);
    }
    
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}

/**
 * Create settings modal
 */
function createSettingsModal() {
    const modal = document.createElement('div');
    modal.id = 'settingsModal';
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Dashboard Settings</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Auto-refresh</label>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="autoRefreshToggle">
                            <label class="form-check-label" for="autoRefreshToggle">
                                Enable automatic data refresh (every 30 minutes)
                            </label>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Theme</label>
                        <select class="form-select" id="themeSelect">
                            <option value="auto">Auto (System)</option>
                            <option value="light">Light</option>
                            <option value="dark">Dark</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="saveSettings()">Save Changes</button>
                </div>
            </div>
        </div>
    `;
    
    // Load current settings
    setTimeout(() => {
        loadCurrentSettings();
    }, 100);
    
    return modal;
}

/**
 * Load current settings into modal
 */
function loadCurrentSettings() {
    try {
        const prefs = JSON.parse(localStorage.getItem('threatDashboardPrefs') || '{}');
        
        const autoRefreshToggle = document.getElementById('autoRefreshToggle');
        if (autoRefreshToggle) {
            autoRefreshToggle.checked = prefs.autoRefresh !== false;
        }
        
        const themeSelect = document.getElementById('themeSelect');
        if (themeSelect) {
            themeSelect.value = prefs.theme || 'auto';
        }
    } catch (error) {
        console.warn('Error loading settings:', error);
    }
}

/**
 * Save settings
 */
function saveSettings() {
    try {
        const autoRefreshToggle = document.getElementById('autoRefreshToggle');
        const themeSelect = document.getElementById('themeSelect');
        
        const settings = {
            autoRefresh: autoRefreshToggle?.checked !== false,
            theme: themeSelect?.value || 'auto'
        };
        
        // Save to localStorage
        saveUserPreferences(settings);
        
        // Apply settings immediately
        setAutoRefresh(settings.autoRefresh);
        applyTheme(settings.theme);
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
        modal.hide();
        
        showAlert('Settings saved successfully!', 'success');
        
    } catch (error) {
        console.error('Error saving settings:', error);
        showAlert('Failed to save settings', 'danger');
    }
}

/**
 * Apply theme setting
 */
function applyTheme(theme) {
    const body = document.body;
    
    // Remove existing theme classes
    body.classList.remove('light-theme', 'dark-theme');
    
    switch (theme) {
        case 'light':
            body.classList.add('light-theme');
            break;
        case 'dark':
            body.classList.add('dark-theme');
            break;
        case 'auto':
        default:
            // Use system preference
            if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
                body.classList.add('dark-theme');
            } else {
                body.classList.add('light-theme');
            }
            break;
    }
}

/**
 * Initialize charts if Chart.js is available
 */
function initializeCharts() {
    // Threat severity distribution chart
    initializeSeverityChart();
    
    // Threat sources chart
    initializeSourcesChart();
    
    // Timeline chart
    initializeTimelineChart();
}

/**
 * Initialize severity distribution chart
 */
function initializeSeverityChart() {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const stats = dashboardData.stats;
    
    chartInstances.severity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    stats.critical_threats || 0,
                    stats.high_threats || 0,
                    stats.medium_threats || 0,
                    stats.low_threats || 0
                ],
                backgroundColor: [
                    '#8b0000',  // Critical - Dark red
                    '#ff4444',  // High - Red
                    '#ff8800',  // Medium - Orange
                    '#4caf50'   // Low - Green
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Initialize sources distribution chart
 */
function initializeSourcesChart() {
    const canvas = document.getElementById('sourcesChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Mock data - in real implementation, get from API
    const sourceData = {
        'MITRE ATT&CK': 150,
        'CISA': 45,
        'AlienVault OTX': 78,
        'RSS Feeds': 92
    };
    
    chartInstances.sources = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(sourceData),
            datasets: [{
                label: 'Threats by Source',
                data: Object.values(sourceData),
                backgroundColor: [
                    '#8b5cf6',  // MITRE - Purple
                    '#0dcaf0',  // CISA - Blue
                    '#00ff88',  // OTX - Green
                    '#6c757d'   // RSS - Gray
                ],
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

/**
 * Initialize timeline chart
 */
function initializeTimelineChart() {
    const canvas = document.getElementById('timelineChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Generate mock timeline data for last 7 days
    const labels = [];
    const data = [];
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        data.push(Math.floor(Math.random() * 20) + 5); // Random data for demo
    }
    
    chartInstances.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'New Threats',
                data: data,
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#667eea',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            elements: {
                point: {
                    hoverRadius: 6
                }
            }
        }
    });
}

/**
 * Set up dashboard-specific keyboard shortcuts
 */
function setupDashboardShortcuts() {
    document.addEventListener('keydown', function(event) {
        // Alt + 1-4: Navigate to different sections
        if (event.altKey && !event.ctrlKey && !event.metaKey) {
            switch (event.key) {
                case '1':
                    event.preventDefault();
                    window.location.href = '/ttps';
                    break;
                case '2':
                    event.preventDefault();
                    window.location.href = '/actors';
                    break;
                case '3':
                    event.preventDefault();
                    window.location.href = '/tools';
                    break;
                case '4':
                    event.preventDefault();
                    window.location.href = '/about';
                    break;
            }
        }
        
        // Ctrl/Cmd + E: Export data
        if ((event.ctrlKey || event.metaKey) && event.key === 'e') {
            event.preventDefault();
            exportDashboardData();
        }
        
        // Ctrl/Cmd + ,: Open settings
        if ((event.ctrlKey || event.metaKey) && event.key === ',') {
            event.preventDefault();
            openSettingsModal();
        }
    });
}

/**
 * Update chart data
 */
function updateChartData(chartName, newData) {
    const chart = chartInstances[chartName];
    if (!chart) return;
    
    if (chartName === 'severity') {
        chart.data.datasets[0].data = [
            newData.critical_threats || 0,
            newData.high_threats || 0,
            newData.medium_threats || 0,
            newData.low_threats || 0
        ];
    }
    
    chart.update('none'); // Update without animation for real-time updates
}

/**
 * Resize charts when window resizes
 */
function resizeCharts() {
    Object.values(chartInstances).forEach(chart => {
        if (chart && typeof chart.resize === 'function') {
            chart.resize();
        }
    });
}

/**
 * Clean up dashboard resources
 */
function cleanupDashboard() {
    // Clear intervals
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
    
    // Destroy charts
    Object.values(chartInstances).forEach(chart => {
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    });
    chartInstances = {};
}

// Handle window resize for charts
window.addEventListener('resize', debounce(resizeCharts, 250));

// Clean up on page unload
window.addEventListener('beforeunload', cleanupDashboard);

// Make functions available globally for inline event handlers
window.saveSettings = saveSettings;
window.showAllThreatItems = showAllThreatItems;

// Export dashboard functionality
window.Dashboard = {
    loadDashboardData,
    updateStatsDisplay,
    exportDashboardData,
    openSettingsModal,
    updateChartData,
    resizeCharts
};