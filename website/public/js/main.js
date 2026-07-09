// Main JavaScript for Squawk DNS Website

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initCopyButtons();
    initAnimations();
    initVersionInfo();
    initContactForms();
});

// Copy to clipboard functionality
function initCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const textToCopy = this.dataset.copy;
            
            if (!textToCopy) return;
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                showNotification('Copied to clipboard!', 'success');
                
                // Visual feedback
                const originalContent = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
                this.classList.add('success-flash');
                
                setTimeout(() => {
                    this.innerHTML = originalContent;
                    this.classList.remove('success-flash');
                }, 2000);
                
            } catch (err) {
                console.error('Failed to copy text: ', err);
                showNotification('Failed to copy to clipboard', 'error');
                this.classList.add('error-flash');
                
                setTimeout(() => {
                    this.classList.remove('error-flash');
                }, 1000);
            }
        });
    });
}

// Scroll animations
function initAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);
    
    // Observe all fade-in elements
    document.querySelectorAll('.fade-in').forEach(el => {
        observer.observe(el);
    });
    
    // Add fade-in class to cards and feature items
    document.querySelectorAll('.card, .feature-card, .stat-item').forEach(el => {
        el.classList.add('fade-in');
        observer.observe(el);
    });
}

// Version information
function initVersionInfo() {
    // Load version from API
    fetch('/api/version')
        .then(response => response.json())
        .then(data => {
            // Update all version elements
            document.querySelectorAll('#latest-version, #version-info').forEach(el => {
                if (el) el.textContent = data.version;
            });
            
            // Update download URLs if present
            updateDownloadUrls(data);
        })
        .catch(error => {
            console.warn('Could not load version info:', error);
            // Fallback to hardcoded version
            document.querySelectorAll('#latest-version, #version-info').forEach(el => {
                if (el) el.textContent = 'v1.1.1';
            });
        });
}

// Update download URLs with current version
function updateDownloadUrls(versionData) {
    const version = versionData.version.replace('v', '');
    const baseUrl = 'https://github.com/penguincloud/squawk/releases/latest/download/';
    
    // Update download links
    const downloadLinks = {
        'deb-amd64': `${baseUrl}squawk-dns-client_${version}_amd64.deb`,
        'deb-arm64': `${baseUrl}squawk-dns-client_${version}_arm64.deb`,
        'macos-universal': `${baseUrl}squawk-dns-client-${version}-darwin-universal.tar.gz`,
        'windows-amd64': `${baseUrl}squawk-dns-client-${version}-windows-amd64.zip`,
        'checksums': `${baseUrl}SHA256SUMS`
    };
    
    Object.entries(downloadLinks).forEach(([key, url]) => {
        const link = document.querySelector(`a[data-download="${key}"]`);
        if (link) {
            link.href = url;
        }
    });
}

// Contact forms and mailto links
function initContactForms() {
    // Add tracking for mailto links
    document.querySelectorAll('a[href^="mailto:sales@penguincloud.io"]').forEach(link => {
        link.addEventListener('click', function() {
            // Track sales contact attempts
            if (typeof gtag !== 'undefined') {
                gtag('event', 'contact_sales', {
                    event_category: 'engagement',
                    event_label: 'mailto_click'
                });
            }
        });
    });
    
    // Add click tracking for download buttons
    document.querySelectorAll('a[href*="github.com"], a[href*="docker.com"]').forEach(link => {
        link.addEventListener('click', function() {
            const url = this.href;
            let category = 'external_link';
            
            if (url.includes('github.com')) {
                category = 'github_download';
            } else if (url.includes('docker')) {
                category = 'docker_download';
            }
            
            if (typeof gtag !== 'undefined') {
                gtag('event', 'download_click', {
                    event_category: category,
                    event_label: url
                });
            }
        });
    });
}

// Notification system
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible position-fixed`;
    notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    `;
    
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas fa-${getNotificationIcon(type)} me-2"></i>
            <span>${message}</span>
            <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Pricing calculator (if needed)
function calculatePricing(users) {
    const pricePerUser = 5; // $5 per user per month
    const monthlyTotal = users * pricePerUser;
    const annualTotal = monthlyTotal * 12 * 0.9; // 10% annual discount
    
    return {
        monthly: monthlyTotal,
        annual: annualTotal,
        savings: (monthlyTotal * 12) - annualTotal
    };
}

// Search functionality (if implementing search)
function initSearch() {
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    
    if (!searchInput || !searchResults) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            searchResults.innerHTML = '';
            searchResults.classList.add('d-none');
            return;
        }
        
        searchTimeout = setTimeout(() => {
            performSearch(query);
        }, 300);
    });
}

// Performance monitoring
function initPerformanceMonitoring() {
    // Log page load time
    window.addEventListener('load', function() {
        const loadTime = performance.now();
        console.log(`Page loaded in ${loadTime.toFixed(2)}ms`);
        
        // Send to analytics if available
        if (typeof gtag !== 'undefined') {
            gtag('event', 'page_load_time', {
                event_category: 'performance',
                value: Math.round(loadTime)
            });
        }
    });
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript error:', e.error);
    
    // Don't spam users with error notifications for minor issues
    if (e.error && e.error.stack && e.error.stack.includes('Network Error')) {
        console.warn('Network error detected, user may be offline');
        return;
    }
});

// Initialize performance monitoring
initPerformanceMonitoring();

// Expose useful functions globally
window.SquawkDNS = {
    showNotification,
    calculatePricing,
    version: '1.1.1'
};