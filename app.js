// Password Manager Application
class PasswordManager {
    constructor() {
        this.currentUser = null;
        this.passwords = [];
        this.isAuthenticated = false;
        this.generatedPassword = '';
        this.editingPasswordId = null;
        this.deletePasswordId = null;
        
        // Sample data from the application data
        this.samplePasswords = [
            {
                id: 1,
                title: "Gmail",
                website: "https://gmail.com",
                username: "user@example.com",
                password: "SecureGmail123!",
                notes: "Personal email account",
                created_at: "2024-01-15",
                strength: 85
            },
            {
                id: 2,
                title: "GitHub",
                website: "https://github.com",
                username: "developer_user",
                password: "Dev_Secure456#",
                notes: "Development repository",
                created_at: "2024-01-20",
                strength: 92
            },
            {
                id: 3,
                title: "Banking",
                website: "https://mybank.com",
                username: "john.doe",
                password: "Bank_Pass789$",
                notes: "Main banking account",
                created_at: "2024-02-01",
                strength: 88
            }
        ];
        
        this.strengthLevels = {
            veryWeak: {min: 0, max: 19, color: "#ff4757", text: "Very Weak"},
            weak: {min: 20, max: 39, color: "#ff6b35", text: "Weak"},
            moderate: {min: 40, max: 59, color: "#ffa726", text: "Moderate"},
            strong: {min: 60, max: 79, color: "#4caf50", text: "Strong"},
            veryStrong: {min: 80, max: 100, color: "#2e7d32", text: "Very Strong"}
        };
        
        // Wait for DOM to be fully loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }
    
    init() {
        console.log('Initializing Password Manager...');
        this.initializeLucideIcons();
        this.setupEventListeners();
        this.checkAuthState();
    }
    
    initializeLucideIcons() {
        // Initialize Lucide icons with error handling
        try {
            if (typeof lucide !== 'undefined' && lucide.createIcons) {
                lucide.createIcons();
            }
        } catch (error) {
            console.warn('Lucide icons not available:', error);
        }
    }
    
    setupEventListeners() {
        console.log('Setting up event listeners...');
        
        // Authentication form listeners
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const showRegisterBtn = document.getElementById('show-register');
        const showLoginBtn = document.getElementById('show-login');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }
        
        if (showRegisterBtn) {
            showRegisterBtn.addEventListener('click', (e) => this.showRegisterForm(e));
        }
        
        if (showLoginBtn) {
            showLoginBtn.addEventListener('click', (e) => this.showLoginForm(e));
        }
        
        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }
        
        // Password toggle listeners
        document.querySelectorAll('.password-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => this.togglePasswordVisibility(e));
        });
        
        // Dashboard listeners
        const addPasswordBtn = document.getElementById('add-password-btn');
        const generatePasswordBtn = document.getElementById('generate-password-btn');
        const searchInput = document.getElementById('search-input');
        
        if (addPasswordBtn) {
            addPasswordBtn.addEventListener('click', () => this.showPasswordModal());
        }
        
        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', () => this.showGeneratorModal());
        }
        
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.handleSearch(e));
        }
        
        // Modal listeners
        this.setupModalListeners();
        
        // Password strength listeners
        const registerPassword = document.getElementById('register-password');
        const passwordValue = document.getElementById('password-value');
        
        if (registerPassword) {
            registerPassword.addEventListener('input', (e) => this.updatePasswordStrength(e.target.value, 'register'));
        }
        
        if (passwordValue) {
            passwordValue.addEventListener('input', (e) => this.updatePasswordStrength(e.target.value, 'form'));
        }
        
        // Generator listeners
        this.setupGeneratorListeners();
    }
    
    setupModalListeners() {
        // Generator modal
        const generatorClose = document.getElementById('generator-close');
        const generatorOverlay = document.getElementById('generator-overlay');
        
        if (generatorClose) {
            generatorClose.addEventListener('click', () => this.hideGeneratorModal());
        }
        
        if (generatorOverlay) {
            generatorOverlay.addEventListener('click', () => this.hideGeneratorModal());
        }
        
        // Password modal
        const passwordClose = document.getElementById('password-close');
        const passwordOverlay = document.getElementById('password-overlay');
        const cancelPassword = document.getElementById('cancel-password');
        const passwordForm = document.getElementById('password-form');
        const useGenerated = document.getElementById('use-generated');
        
        if (passwordClose) {
            passwordClose.addEventListener('click', () => this.hidePasswordModal());
        }
        
        if (passwordOverlay) {
            passwordOverlay.addEventListener('click', () => this.hidePasswordModal());
        }
        
        if (cancelPassword) {
            cancelPassword.addEventListener('click', () => this.hidePasswordModal());
        }
        
        if (passwordForm) {
            passwordForm.addEventListener('submit', (e) => this.handlePasswordSubmit(e));
        }
        
        if (useGenerated) {
            useGenerated.addEventListener('click', () => this.useGeneratedPassword());
        }
        
        // Delete modal
        const deleteClose = document.getElementById('delete-close');
        const deleteOverlay = document.getElementById('delete-overlay');
        const cancelDelete = document.getElementById('cancel-delete');
        const confirmDelete = document.getElementById('confirm-delete');
        
        if (deleteClose) {
            deleteClose.addEventListener('click', () => this.hideDeleteModal());
        }
        
        if (deleteOverlay) {
            deleteOverlay.addEventListener('click', () => this.hideDeleteModal());
        }
        
        if (cancelDelete) {
            cancelDelete.addEventListener('click', () => this.hideDeleteModal());
        }
        
        if (confirmDelete) {
            confirmDelete.addEventListener('click', () => this.confirmDelete());
        }
    }
    
    setupGeneratorListeners() {
        const generateBtn = document.getElementById('generate-btn');
        const copyGenerated = document.getElementById('copy-generated');
        const passwordLength = document.getElementById('password-length');
        const lengthValue = document.getElementById('length-value');
        
        if (generateBtn) {
            generateBtn.addEventListener('click', () => this.generatePassword());
        }
        
        if (copyGenerated) {
            copyGenerated.addEventListener('click', () => {
                const generatedPassword = document.getElementById('generated-password');
                if (generatedPassword) {
                    this.copyToClipboard(generatedPassword.value);
                }
            });
        }
        
        if (passwordLength && lengthValue) {
            passwordLength.addEventListener('input', (e) => {
                lengthValue.textContent = e.target.value;
                this.generatePassword();
            });
        }
        
        // Checkbox listeners
        ['include-uppercase', 'include-lowercase', 'include-numbers', 'include-symbols'].forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.addEventListener('change', () => this.generatePassword());
            }
        });
        
        // Generate initial password
        setTimeout(() => this.generatePassword(), 500);
    }
    
    // Authentication Methods
    handleLogin(e) {
        e.preventDefault();
        console.log('Handling login...');
        
        const emailInput = document.getElementById('login-email');
        const passwordInput = document.getElementById('login-password');
        
        if (!emailInput || !passwordInput) {
            console.error('Login form elements not found');
            return;
        }
        
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        
        console.log('Login attempt for:', email);
        
        if (!email || !password) {
            this.showToast('Please enter both email and password', 'error');
            return;
        }
        
        if (this.validateLogin(email, password)) {
            this.currentUser = { email };
            this.isAuthenticated = true;
            this.loadUserData();
            
            // Use setTimeout to ensure DOM updates properly
            setTimeout(() => {
                this.showDashboard();
                this.showToast('Welcome back!', 'success');
            }, 100);
        } else {
            this.showToast('Invalid credentials. Try any email with password length >= 8 characters.', 'error');
        }
    }
    
    handleRegister(e) {
        e.preventDefault();
        console.log('Handling register...');
        
        const emailInput = document.getElementById('register-email');
        const passwordInput = document.getElementById('register-password');
        const confirmPasswordInput = document.getElementById('confirm-password');
        
        if (!emailInput || !passwordInput || !confirmPasswordInput) {
            console.error('Register form elements not found');
            return;
        }
        
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        console.log('Register attempt for:', email);
        
        if (!email || !password || !confirmPassword) {
            this.showToast('Please fill in all fields', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showToast('Passwords do not match', 'error');
            return;
        }
        
        const strength = this.calculatePasswordStrength(password);
        if (strength < 40) {
            this.showToast('Master password is too weak. Please use a stronger password.', 'error');
            return;
        }
        
        // Simulate account creation
        this.currentUser = { email };
        this.isAuthenticated = true;
        this.passwords = [...this.samplePasswords]; // Load sample data for demo
        this.saveUserData();
        
        // Use setTimeout to ensure DOM updates properly
        setTimeout(() => {
            this.showDashboard();
            this.showToast('Account created successfully!', 'success');
        }, 100);
    }
    
    validateLogin(email, password) {
        // For demo purposes, accept any email/password combination with minimum requirements
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && password && password.length >= 8;
    }
    
    handleLogout() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.passwords = [];
        this.editingPasswordId = null;
        this.deletePasswordId = null;
        localStorage.removeItem('pm_user');
        
        // Clear forms
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        if (loginForm) loginForm.reset();
        if (registerForm) registerForm.reset();
        
        this.showAuthSection();
        this.showToast('Logged out successfully', 'success');
    }
    
    checkAuthState() {
        // For demo purposes, always start with auth screen
        this.showAuthSection();
    }
    
    // UI Navigation Methods
    showRegisterForm(e) {
        e.preventDefault();
        console.log('Showing register form...');
        
        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        
        if (loginForm && registerForm) {
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
        }
    }
    
    showLoginForm(e) {
        e.preventDefault();
        console.log('Showing login form...');
        
        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        
        if (loginForm && registerForm) {
            registerForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
        }
    }
    
    showAuthSection() {
        console.log('Showing auth section...');
        const authSection = document.getElementById('auth-section');
        const dashboard = document.getElementById('dashboard');
        
        if (authSection) {
            authSection.classList.remove('hidden');
            console.log('Auth section shown');
        } else {
            console.error('Auth section not found');
        }
        
        if (dashboard) {
            dashboard.classList.add('hidden');
            console.log('Dashboard hidden');
        } else {
            console.error('Dashboard not found');
        }
    }
    
    showDashboard() {
        console.log('Showing dashboard...');
        const authSection = document.getElementById('auth-section');
        const dashboard = document.getElementById('dashboard');
        const userEmail = document.getElementById('user-email');
        
        if (!authSection || !dashboard) {
            console.error('Required DOM elements not found:', {authSection: !!authSection, dashboard: !!dashboard});
            return;
        }
        
        // Hide auth section
        authSection.classList.add('hidden');
        console.log('Auth section hidden');
        
        // Show dashboard
        dashboard.classList.remove('hidden');
        console.log('Dashboard shown');
        
        // Set user email
        if (userEmail && this.currentUser) {
            userEmail.textContent = this.currentUser.email;
            console.log('User email set:', this.currentUser.email);
        }
        
        // Initialize dashboard content
        setTimeout(() => {
            this.renderPasswordList();
            this.updatePasswordCount();
            this.initializeLucideIcons();
        }, 50);
    }
    
    // Data Management Methods
    loadUserData() {
        // For demo, always load sample data
        this.passwords = [...this.samplePasswords];
        console.log('Loaded sample data:', this.passwords.length, 'passwords');
        this.saveUserData();
    }
    
    saveUserData() {
        if (this.currentUser) {
            try {
                localStorage.setItem('pm_user', JSON.stringify(this.currentUser));
                localStorage.setItem(`pm_data_${this.currentUser.email}`, JSON.stringify(this.passwords));
                console.log('Data saved successfully');
            } catch (error) {
                console.error('Error saving data:', error);
            }
        }
    }
    
    // Password Management Methods
    renderPasswordList(filteredPasswords = null) {
        console.log('Rendering password list...');
        const passwordList = document.getElementById('password-list');
        const emptyState = document.getElementById('empty-state');
        
        if (!passwordList) {
            console.error('Password list element not found');
            return;
        }
        
        const passwords = filteredPasswords || this.passwords;
        console.log('Rendering', passwords.length, 'passwords');
        
        if (passwords.length === 0) {
            passwordList.innerHTML = '';
            if (emptyState) emptyState.classList.remove('hidden');
            return;
        }
        
        if (emptyState) emptyState.classList.add('hidden');
        passwordList.innerHTML = passwords.map(password => this.renderPasswordRow(password)).join('');
        
        // Re-initialize Lucide icons for the new content
        setTimeout(() => {
            this.initializeLucideIcons();
            this.setupPasswordRowListeners();
        }, 50);
    }
    
    renderPasswordRow(password) {
        const strengthInfo = this.getStrengthInfo(password.strength);
        let websiteDisplay = 'Not specified';
        
        if (password.website) {
            try {
                const url = new URL(password.website);
                websiteDisplay = `<a href="${password.website}" target="_blank">${url.hostname}</a>`;
            } catch (e) {
                websiteDisplay = `<a href="${password.website}" target="_blank">${password.website}</a>`;
            }
        }
        
        return `
            <tr data-password-id="${password.id}">
                <td><strong>${this.escapeHtml(password.title)}</strong></td>
                <td class="website-cell">${websiteDisplay}</td>
                <td>${this.escapeHtml(password.username || 'Not specified')}</td>
                <td class="password-cell">
                    <span class="password-masked" data-password="${this.escapeHtml(password.password)}">••••••••</span>
                    <button class="action-btn reveal-password" title="Show password" type="button">
                        <i data-lucide="eye"></i>
                    </button>
                    <button class="action-btn copy-password" title="Copy password" data-password="${this.escapeHtml(password.password)}" type="button">
                        <i data-lucide="copy"></i>
                    </button>
                </td>
                <td class="strength-cell">
                    <span class="strength-badge" style="background-color: ${strengthInfo.color}">${strengthInfo.text}</span>
                </td>
                <td class="actions-cell">
                    <button class="action-btn edit-password" title="Edit" data-id="${password.id}" type="button">
                        <i data-lucide="edit"></i>
                    </button>
                    <button class="action-btn delete-password" title="Delete" data-id="${password.id}" data-title="${this.escapeHtml(password.title)}" type="button">
                        <i data-lucide="trash-2"></i>
                    </button>
                </td>
            </tr>
        `;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    setupPasswordRowListeners() {
        console.log('Setting up password row listeners...');
        
        // Reveal password buttons
        document.querySelectorAll('.reveal-password').forEach(btn => {
            btn.addEventListener('click', (e) => this.togglePasswordReveal(e));
        });
        
        // Copy password buttons
        document.querySelectorAll('.copy-password').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const password = e.target.closest('.copy-password').dataset.password;
                this.copyToClipboard(password);
            });
        });
        
        // Edit buttons
        document.querySelectorAll('.edit-password').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.target.closest('.edit-password').dataset.id;
                this.editPassword(id);
            });
        });
        
        // Delete buttons
        document.querySelectorAll('.delete-password').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const button = e.target.closest('.delete-password');
                this.showDeleteModal(button.dataset.id, button.dataset.title);
            });
        });
    }
    
    togglePasswordReveal(e) {
        const button = e.target.closest('.reveal-password');
        const passwordSpan = button.parentNode.querySelector('.password-masked');
        const icon = button.querySelector('i');
        
        if (passwordSpan.classList.contains('password-visible')) {
            passwordSpan.textContent = '••••••••';
            passwordSpan.classList.remove('password-visible');
            icon.setAttribute('data-lucide', 'eye');
        } else {
            passwordSpan.textContent = passwordSpan.dataset.password;
            passwordSpan.classList.add('password-visible');
            icon.setAttribute('data-lucide', 'eye-off');
        }
        
        this.initializeLucideIcons();
    }
    
    editPassword(id) {
        const password = this.passwords.find(p => p.id == id);
        if (!password) return;
        
        this.editingPasswordId = parseInt(id);
        
        const modalTitle = document.getElementById('password-modal-title');
        const passwordId = document.getElementById('password-id');
        const passwordTitle = document.getElementById('password-title');
        const passwordWebsite = document.getElementById('password-website');
        const passwordUsername = document.getElementById('password-username');
        const passwordValue = document.getElementById('password-value');
        const passwordNotes = document.getElementById('password-notes');
        
        if (modalTitle) modalTitle.textContent = 'Edit Password';
        if (passwordId) passwordId.value = id;
        if (passwordTitle) passwordTitle.value = password.title;
        if (passwordWebsite) passwordWebsite.value = password.website || '';
        if (passwordUsername) passwordUsername.value = password.username || '';
        if (passwordValue) passwordValue.value = password.password;
        if (passwordNotes) passwordNotes.value = password.notes || '';
        
        this.updatePasswordStrength(password.password, 'form');
        this.showPasswordModal();
    }
    
    showDeleteModal(id, title) {
        this.deletePasswordId = parseInt(id);
        const deleteTitle = document.getElementById('delete-title');
        const deleteModal = document.getElementById('delete-modal');
        
        if (deleteTitle) deleteTitle.textContent = title;
        if (deleteModal) deleteModal.classList.add('show');
    }
    
    hideDeleteModal() {
        const deleteModal = document.getElementById('delete-modal');
        if (deleteModal) deleteModal.classList.remove('show');
        this.deletePasswordId = null;
    }
    
    confirmDelete() {
        if (this.deletePasswordId) {
            this.passwords = this.passwords.filter(p => p.id !== this.deletePasswordId);
            this.saveUserData();
            this.renderPasswordList();
            this.updatePasswordCount();
            this.hideDeleteModal();
            this.showToast('Password deleted successfully', 'success');
        }
    }
    
    // Modal Methods
    showPasswordModal() {
        const passwordModal = document.getElementById('password-modal');
        
        if (!this.editingPasswordId) {
            const modalTitle = document.getElementById('password-modal-title');
            const passwordForm = document.getElementById('password-form');
            const passwordId = document.getElementById('password-id');
            
            if (modalTitle) modalTitle.textContent = 'Add Password';
            if (passwordForm) passwordForm.reset();
            if (passwordId) passwordId.value = '';
            this.updatePasswordStrength('', 'form');
        }
        
        if (passwordModal) passwordModal.classList.add('show');
    }
    
    hidePasswordModal() {
        const passwordModal = document.getElementById('password-modal');
        if (passwordModal) passwordModal.classList.remove('show');
        this.editingPasswordId = null;
    }
    
    showGeneratorModal() {
        const generatorModal = document.getElementById('generator-modal');
        if (generatorModal) generatorModal.classList.add('show');
        
        // Generate password when modal opens
        setTimeout(() => this.generatePassword(), 100);
    }
    
    hideGeneratorModal() {
        const generatorModal = document.getElementById('generator-modal');
        if (generatorModal) generatorModal.classList.remove('show');
    }
    
    // Password Form Handling
    handlePasswordSubmit(e) {
        e.preventDefault();
        
        const titleInput = document.getElementById('password-title');
        const websiteInput = document.getElementById('password-website');
        const usernameInput = document.getElementById('password-username');
        const passwordInput = document.getElementById('password-value');
        const notesInput = document.getElementById('password-notes');
        
        if (!titleInput || !passwordInput) {
            this.showToast('Form elements not found', 'error');
            return;
        }
        
        const formData = {
            title: titleInput.value.trim(),
            website: websiteInput ? websiteInput.value.trim() : '',
            username: usernameInput ? usernameInput.value.trim() : '',
            password: passwordInput.value,
            notes: notesInput ? notesInput.value.trim() : ''
        };
        
        if (!formData.title || !formData.password) {
            this.showToast('Title and password are required', 'error');
            return;
        }
        
        const strength = this.calculatePasswordStrength(formData.password);
        formData.strength = strength;
        formData.created_at = new Date().toISOString().split('T')[0];
        
        if (this.editingPasswordId) {
            // Update existing password
            const index = this.passwords.findIndex(p => p.id === this.editingPasswordId);
            if (index !== -1) {
                formData.id = this.editingPasswordId;
                this.passwords[index] = formData;
                this.showToast('Password updated successfully', 'success');
            }
        } else {
            // Add new password
            formData.id = Date.now();
            this.passwords.push(formData);
            this.showToast('Password added successfully', 'success');
        }
        
        this.saveUserData();
        this.renderPasswordList();
        this.updatePasswordCount();
        this.hidePasswordModal();
    }
    
    useGeneratedPassword() {
        if (this.generatedPassword) {
            const passwordValue = document.getElementById('password-value');
            if (passwordValue) {
                passwordValue.value = this.generatedPassword;
                this.updatePasswordStrength(this.generatedPassword, 'form');
                this.showToast('Generated password applied', 'success');
            }
        }
    }
    
    // Search and Filter
    handleSearch(e) {
        const query = e.target.value.toLowerCase();
        if (!query) {
            this.renderPasswordList();
            return;
        }
        
        const filtered = this.passwords.filter(password => 
            password.title.toLowerCase().includes(query) ||
            (password.website && password.website.toLowerCase().includes(query)) ||
            (password.username && password.username.toLowerCase().includes(query))
        );
        
        this.renderPasswordList(filtered);
    }
    
    // Password Generator
    generatePassword() {
        const lengthInput = document.getElementById('password-length');
        const uppercaseCheck = document.getElementById('include-uppercase');
        const lowercaseCheck = document.getElementById('include-lowercase');
        const numbersCheck = document.getElementById('include-numbers');
        const symbolsCheck = document.getElementById('include-symbols');
        
        if (!lengthInput) return;
        
        const length = parseInt(lengthInput.value) || 16;
        const includeUppercase = uppercaseCheck ? uppercaseCheck.checked : true;
        const includeLowercase = lowercaseCheck ? lowercaseCheck.checked : true;
        const includeNumbers = numbersCheck ? numbersCheck.checked : true;
        const includeSymbols = symbolsCheck ? symbolsCheck.checked : true;
        
        let charset = '';
        if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (includeNumbers) charset += '0123456789';
        if (includeSymbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';
        
        if (!charset) {
            this.showToast('Please select at least one character type', 'error');
            return;
        }
        
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        
        this.generatedPassword = password;
        const generatedPasswordInput = document.getElementById('generated-password');
        if (generatedPasswordInput) {
            generatedPasswordInput.value = password;
        }
        
        this.updatePasswordStrength(password, 'generated');
    }
    
    // Password Strength Calculation
    calculatePasswordStrength(password) {
        if (!password) return 0;
        
        let score = 0;
        const length = password.length;
        
        // Length scoring
        if (length >= 8) score += 25;
        if (length >= 12) score += 25;
        
        // Character type scoring
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 10;
        if (/[^a-zA-Z0-9]/.test(password)) score += 10;
        
        // Bonus for variety
        const uniqueChars = new Set(password).size;
        if (uniqueChars >= length * 0.6) score += 10;
        
        return Math.min(100, score);
    }
    
    getStrengthInfo(score) {
        for (const [level, info] of Object.entries(this.strengthLevels)) {
            if (score >= info.min && score <= info.max) {
                return info;
            }
        }
        return this.strengthLevels.veryWeak;
    }
    
    updatePasswordStrength(password, context) {
        const strength = this.calculatePasswordStrength(password);
        const strengthInfo = this.getStrengthInfo(strength);
        
        const barId = context === 'register' ? 'register-strength-bar' : 
                      context === 'generated' ? 'generated-strength-bar' : 'form-strength-bar';
        const textId = context === 'register' ? 'register-strength-text' : 
                       context === 'generated' ? 'generated-strength-text' : 'form-strength-text';
        
        const bar = document.getElementById(barId);
        const text = document.getElementById(textId);
        
        if (bar && text) {
            bar.style.width = `${strength}%`;
            bar.style.backgroundColor = strengthInfo.color;
            text.textContent = password ? `${strengthInfo.text} (${strength}%)` : 'Enter a password';
        }
    }
    
    // Utility Methods
    togglePasswordVisibility(e) {
        const button = e.target.closest('.password-toggle');
        if (!button) return;
        
        const targetId = button.dataset.target;
        const input = document.getElementById(targetId);
        const icon = button.querySelector('i');
        
        if (!input || !icon) return;
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.setAttribute('data-lucide', 'eye-off');
        } else {
            input.type = 'password';
            icon.setAttribute('data-lucide', 'eye');
        }
        
        this.initializeLucideIcons();
    }
    
    updatePasswordCount() {
        const count = this.passwords.length;
        const passwordCountEl = document.getElementById('password-count');
        if (passwordCountEl) {
            passwordCountEl.textContent = `${count} password${count !== 1 ? 's' : ''}`;
        }
    }
    
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('Copied to clipboard', 'success');
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showToast('Copied to clipboard', 'success');
        }
    }
    
    showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        if (!toast) return;
        
        // Clear any existing content
        toast.innerHTML = '';
        
        // Add icon based on type
        const iconName = type === 'success' ? 'check-circle' : 'alert-circle';
        toast.innerHTML = `<i data-lucide="${iconName}"></i>${message}`;
        
        toast.className = `toast ${type}`;
        toast.classList.add('show');
        
        // Initialize icons for the toast
        this.initializeLucideIcons();
        
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing Password Manager...');
    new PasswordManager();
});

// Also initialize if DOM is already loaded
if (document.readyState !== 'loading') {
    console.log('DOM already loaded, initializing Password Manager...');
    new PasswordManager();
}