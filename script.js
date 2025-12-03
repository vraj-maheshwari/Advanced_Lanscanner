// LAN Scanner Pro Website JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for navigation links
    const navLinks = document.querySelectorAll('.nav a, .btn[href^="#"]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetSection = document.querySelector(targetId);
            
            if (targetSection) {
                const headerHeight = document.querySelector('.header').offsetHeight;
                const targetPosition = targetSection.offsetTop - headerHeight - 20;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Header scroll effect
    const header = document.querySelector('.header');
    let lastScrollTop = 0;

    window.addEventListener('scroll', function() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        if (scrollTop > 100) {
            header.style.background = 'rgba(102, 126, 234, 0.95)';
            header.style.backdropFilter = 'blur(10px)';
        } else {
            header.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
            header.style.backdropFilter = 'none';
        }
        
        lastScrollTop = scrollTop;
    });

    // Animate feature cards on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Observe feature cards
    const featureCards = document.querySelectorAll('.feature-card, .tech-category, .impl-card, .screenshot-item');
    featureCards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(card);
    });

    // Download button click tracking
    const downloadBtn = document.querySelector('.download-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', function() {
            // Add download animation
            const icon = this.querySelector('i');
            const originalClass = icon.className;
            
            icon.className = 'fas fa-spinner fa-spin';
            
            setTimeout(() => {
                icon.className = 'fas fa-check';
                setTimeout(() => {
                    icon.className = originalClass;
                }, 2000);
            }, 1000);
            
            // Track download (you can add analytics here)
            console.log('LAN Scanner Pro download initiated');
        });
    }

    // Tech tag hover effects
    const techTags = document.querySelectorAll('.tech-tag');
    techTags.forEach(tag => {
        tag.addEventListener('mouseenter', function() {
            this.style.background = '#4CAF50';
            this.style.color = 'white';
            this.style.transform = 'scale(1.05)';
        });
        
        tag.addEventListener('mouseleave', function() {
            this.style.background = '#e9ecef';
            this.style.color = '#495057';
            this.style.transform = 'scale(1)';
        });
    });

    // Skill tag animation
    const skills = document.querySelectorAll('.skill');
    skills.forEach((skill, index) => {
        skill.style.animationDelay = `${index * 0.1}s`;
        skill.classList.add('skill-animate');
    });

    // Add CSS for skill animation
    const style = document.createElement('style');
    style.textContent = `
        .skill-animate {
            animation: skillPop 0.5s ease forwards;
            opacity: 0;
            transform: scale(0.8);
        }
        
        @keyframes skillPop {
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
    `;
    document.head.appendChild(style);

    // Code snippet copy functionality
    const codeSnippets = document.querySelectorAll('.code-snippet');
    codeSnippets.forEach(snippet => {
        snippet.style.position = 'relative';
        snippet.style.cursor = 'pointer';
        
        const copyBtn = document.createElement('div');
        copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
        copyBtn.style.cssText = `
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255,255,255,0.1);
            color: white;
            padding: 5px 8px;
            border-radius: 4px;
            font-size: 12px;
            opacity: 0;
            transition: opacity 0.3s ease;
            cursor: pointer;
        `;
        
        snippet.appendChild(copyBtn);
        
        snippet.addEventListener('mouseenter', () => {
            copyBtn.style.opacity = '1';
        });
        
        snippet.addEventListener('mouseleave', () => {
            copyBtn.style.opacity = '0';
        });
        
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const code = snippet.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                }, 1000);
            });
        });
    });

    // Network animation enhancement
    const networkNodes = document.querySelectorAll('.network-node');
    networkNodes.forEach((node, index) => {
        node.addEventListener('mouseenter', function() {
            this.style.transform += ' scale(1.5)';
            this.style.zIndex = '10';
        });
        
        node.addEventListener('mouseleave', function() {
            this.style.transform = this.style.transform.replace(' scale(1.5)', '');
            this.style.zIndex = '1';
        });
    });

    // Statistics counter animation
    function animateCounter(element, target, duration = 2000) {
        let start = 0;
        const increment = target / (duration / 16);
        
        function updateCounter() {
            start += increment;
            if (start < target) {
                element.textContent = Math.floor(start);
                requestAnimationFrame(updateCounter);
            } else {
                element.textContent = target;
            }
        }
        
        updateCounter();
    }

    // DNS Resolution Methods Information
    const dnsMethodsInfo = {
        'NetBIOS Resolution': 'Uses nbtstat -A command for Windows NetBIOS name lookup',
        'Reverse DNS': 'Standard reverse DNS lookup using socket.gethostbyaddr()',
        'Ping Resolution': 'Uses ping -a command to resolve hostnames',
        'Timeout Handling': 'Implements proper timeout mechanisms for all DNS operations'
    };

    // Add DNS methods information to implementation section
    const implementationSection = document.querySelector('.implementation');
    if (implementationSection) {
        const dnsContainer = document.createElement('div');
        dnsContainer.className = 'dns-methods-container';
        dnsContainer.innerHTML = `
            <h3><i class="fas fa-globe"></i> DNS Resolution Methods</h3>
            <div class="dns-methods-grid">
                ${Object.entries(dnsMethodsInfo).map(([method, description]) => `
                    <div class="dns-method-item">
                        <h4>${method}</h4>
                        <p>${description}</p>
                    </div>
                `).join('')}
            </div>
        `;
        
        dnsContainer.style.cssText = `
            margin-top: 3rem;
            padding: 2rem;
            background: #f8f9fa;
            border-radius: 12px;
            border-left: 4px solid #4CAF50;
        `;
        
        implementationSection.querySelector('.container').appendChild(dnsContainer);
    }

    // Mobile menu toggle (for future mobile optimization)
    const createMobileMenu = () => {
        const header = document.querySelector('.header-content');
        const nav = document.querySelector('.nav');
        
        const mobileToggle = document.createElement('button');
        mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
        mobileToggle.className = 'mobile-toggle';
        mobileToggle.style.cssText = `
            display: none;
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
        `;
        
        header.appendChild(mobileToggle);
        
        mobileToggle.addEventListener('click', () => {
            nav.classList.toggle('mobile-open');
        });
        
        // Add mobile styles
        const mobileStyle = document.createElement('style');
        mobileStyle.textContent = `
            @media (max-width: 768px) {
                .mobile-toggle {
                    display: block !important;
                }
                
                .nav {
                    position: absolute;
                    top: 100%;
                    left: 0;
                    right: 0;
                    background: rgba(102, 126, 234, 0.95);
                    backdrop-filter: blur(10px);
                    flex-direction: column;
                    padding: 1rem;
                    transform: translateY(-100%);
                    opacity: 0;
                    transition: all 0.3s ease;
                    pointer-events: none;
                }
                
                .nav.mobile-open {
                    transform: translateY(0);
                    opacity: 1;
                    pointer-events: all;
                }
            }
        `;
        document.head.appendChild(mobileStyle);
    };
    
    createMobileMenu();

    // Add loading state to download button
    const addLoadingState = () => {
        const downloadBtn = document.querySelector('.download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function(e) {
                const span = this.querySelector('span');
                const originalText = span.textContent;
                
                span.innerHTML = '<span class="loading"></span> Preparing Download...';
                
                setTimeout(() => {
                    span.textContent = originalText;
                }, 3000);
            });
        }
    };
    
    addLoadingState();

    // Console welcome message
    console.log(`
    🚀 LAN Scanner Pro Website
    ========================
    
    Welcome to the LAN Scanner Pro project page!
    
    Technical Stack:
    - Frontend: HTML5, CSS3, JavaScript
    - Backend: Python 3.x
    - GUI: Tkinter with ttk
    - Networking: socket, ipaddress, subprocess
    - Threading: concurrent.futures, ThreadPoolExecutor
    - Visualization: matplotlib, Canvas
    - Packaging: PyInstaller
    
    Features:
    ✓ Multi-threaded network scanning
    ✓ Banner grabbing and service detection
    ✓ Real-time statistics and visualization
    ✓ Vulnerability assessment hints
    ✓ Export capabilities (CSV, JSON)
    ✓ Modern GUI with dark/light themes
    
    Download the executable and start scanning your network!
    `);
});

// Utility functions
const utils = {
    // Debounce function for performance
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Check if element is in viewport
    isInViewport: (element) => {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    },
    
    // Format file size
    formatFileSize: (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// Export utils for potential future use
window.LANScannerUtils = utils;