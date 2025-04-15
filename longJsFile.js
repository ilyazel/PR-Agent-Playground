/**
 * Comprehensive Task Management System
 * ====================================
 * 
 * A feature-rich JavaScript application for managing tasks, projects, and teams.
 * This system includes:
 * - User authentication and authorization
 * - Task creation, editing, and deletion
 * - Project management
 * - Team collaboration
 * - Analytics and reporting
 * - Data persistence
 * - Notifications
 * - Calendar integration
 * 
 * @author Claude
 * @version 1.0.0
 * @license MIT
 */

// =========================================================================
// CORE UTILITIES AND HELPERS
// =========================================================================

/**
 * Utility functions for common operations
 */
const Utils = {
    /**
     * Generates a unique ID
     * @return {string} A unique identifier
     */
    generateId: function() {
      return Math.random().toString(36).substring(2, 15) + 
             Math.random().toString(36).substring(2, 15);
    },
    
    /**
     * Format a date to a readable string
     * @param {Date} date - The date to format
     * @return {string} Formatted date string
     */
    formatDate: function(date) {
      if (!date) return '';
      return new Date(date).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    },
    
    /**
     * Calculate the difference between two dates in days
     * @param {Date} date1 - First date
     * @param {Date} date2 - Second date
     * @return {number} The difference in days
     */
    daysBetween: function(date1, date2) {
      const oneDay = 24 * 60 * 60 * 1000;
      const firstDate = new Date(date1);
      const secondDate = new Date(date2);
      return Math.round(Math.abs((firstDate - secondDate) / oneDay));
    },
    
    /**
     * Check if a date is in the past
     * @param {Date} date - The date to check
     * @return {boolean} True if the date is in the past
     */
    isDatePast: function(date) {
      return new Date(date) < new Date();
    },
    
    /**
     * Deep clone an object
     * @param {Object} obj - The object to clone
     * @return {Object} A deep clone of the input object
     */
    deepClone: function(obj) {
      return JSON.parse(JSON.stringify(obj));
    },
  
    /**
     * Debounce a function call
     * @param {Function} func - The function to debounce
     * @param {number} wait - The debounce wait time in milliseconds
     * @return {Function} The debounced function
     */
    debounce: function(func, wait) {
      let timeout;
      return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
      };
    },
    
    /**
     * Throttle a function call
     * @param {Function} func - The function to throttle
     * @param {number} limit - The throttle limit in milliseconds
     * @return {Function} The throttled function
     */
    throttle: function(func, limit) {
      let lastFunc;
      let lastRan;
      return function(...args) {
        const context = this;
        if (!lastRan) {
          func.apply(context, args);
          lastRan = Date.now();
        } else {
          clearTimeout(lastFunc);
          lastFunc = setTimeout(() => {
            if ((Date.now() - lastRan) >= limit) {
              func.apply(context, args);
              lastRan = Date.now();
            }
          }, limit - (Date.now() - lastRan));
        }
      };
    },
    
    /**
     * Format bytes to a human-readable string
     * @param {number} bytes - Number of bytes
     * @param {number} decimals - Number of decimal places
     * @return {string} Formatted string
     */
    formatBytes: function(bytes, decimals = 2) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const dm = decimals < 0 ? 0 : decimals;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },
    
    /**
     * Validates an email address format
     * @param {string} email - The email to validate
     * @return {boolean} True if the email is valid
     */
    isValidEmail: function(email) {
      const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
      return re.test(String(email).toLowerCase());
    },
    
    /**
     * Check if a string is empty or just whitespace
     * @param {string} str - The string to check
     * @return {boolean} True if the string is empty or just whitespace
     */
    isEmptyString: function(str) {
      return !str || /^\s*$/.test(str);
    },
    
    /**
     * Convert a string to title case
     * @param {string} str - The string to convert
     * @return {string} The title-cased string
     */
    toTitleCase: function(str) {
      return str.replace(
        /\w\S*/g,
        function(txt) {
          return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
        }
      );
    }
  };
  
  /**
   * Event management system
   */
  class EventEmitter {
    constructor() {
      this.events = {};
    }
    
    /**
     * Subscribe to an event
     * @param {string} event - Event name
     * @param {Function} listener - Event callback
     */
    on(event, listener) {
      if (!this.events[event]) {
        this.events[event] = [];
      }
      this.events[event].push(listener);
    }
    
    /**
     * Unsubscribe from an event
     * @param {string} event - Event name
     * @param {Function} listenerToRemove - Event callback to remove
     */
    off(event, listenerToRemove) {
      if (!this.events[event]) return;
      
      this.events[event] = this.events[event].filter(
        listener => listener !== listenerToRemove
      );
    }
    
    /**
     * Emit an event
     * @param {string} event - Event name
     * @param {*} data - Event data
     */
    emit(event, data) {
      if (!this.events[event]) return;
      
      this.events[event].forEach(listener => {
        listener(data);
      });
    }
    
    /**
     * Subscribe to an event only once
     * @param {string} event - Event name
     * @param {Function} listener - Event callback
     */
    once(event, listener) {
      const onceListener = (data) => {
        listener(data);
        this.off(event, onceListener);
      };
      
      this.on(event, onceListener);
    }
  }
  
  /**
   * Global event bus
   */
  const EventBus = new EventEmitter();
  
  /**
   * HTTP request wrapper
   */
  class HttpClient {
    /**
     * Make a GET request
     * @param {string} url - The URL to fetch
     * @param {Object} headers - Request headers
     * @return {Promise} Promise resolving to the response
     */
    static async get(url, headers = {}) {
      try {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          }
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('GET request failed:', error);
        throw error;
      }
    }
    
    /**
     * Make a POST request
     * @param {string} url - The URL to fetch
     * @param {Object} data - The data to send
     * @param {Object} headers - Request headers
     * @return {Promise} Promise resolving to the response
     */
    static async post(url, data = {}, headers = {}) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: JSON.stringify(data)
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('POST request failed:', error);
        throw error;
      }
    }
    
    /**
     * Make a PUT request
     * @param {string} url - The URL to fetch
     * @param {Object} data - The data to send
     * @param {Object} headers - Request headers
     * @return {Promise} Promise resolving to the response
     */
    static async put(url, data = {}, headers = {}) {
      try {
        const response = await fetch(url, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: JSON.stringify(data)
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('PUT request failed:', error);
        throw error;
      }
    }
    
    /**
     * Make a DELETE request
     * @param {string} url - The URL to fetch
     * @param {Object} headers - Request headers
     * @return {Promise} Promise resolving to the response
     */
    static async delete(url, headers = {}) {
      try {
        const response = await fetch(url, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          }
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('DELETE request failed:', error);
        throw error;
      }
    }
  }
  
  /**
   * Storage management (localStorage wrapper)
   */
  class Storage {
    /**
     * Set an item in storage
     * @param {string} key - The key to store under
     * @param {*} value - The value to store
     */
    static set(key, value) {
      try {
        const serializedValue = JSON.stringify(value);
        localStorage.setItem(key, serializedValue);
      } catch (error) {
        console.error('Error saving to localStorage:', error);
      }
    }
    
    /**
     * Get an item from storage
     * @param {string} key - The key to retrieve
     * @param {*} defaultValue - Default value if key doesn't exist
     * @return {*} The stored value or defaultValue
     */
    static get(key, defaultValue = null) {
      try {
        const serializedValue = localStorage.getItem(key);
        if (serializedValue === null) {
          return defaultValue;
        }
        return JSON.parse(serializedValue);
      } catch (error) {
        console.error('Error reading from localStorage:', error);
        return defaultValue;
      }
    }
    
    /**
     * Remove an item from storage
     * @param {string} key - The key to remove
     */
    static remove(key) {
      try {
        localStorage.removeItem(key);
      } catch (error) {
        console.error('Error removing from localStorage:', error);
      }
    }
    
    /**
     * Clear all items from storage
     */
    static clear() {
      try {
        localStorage.clear();
      } catch (error) {
        console.error('Error clearing localStorage:', error);
      }
    }
    
    /**
     * Get all keys in storage
     * @return {Array} Array of keys
     */
    static keys() {
      try {
        return Object.keys(localStorage);
      } catch (error) {
        console.error('Error getting keys from localStorage:', error);
        return [];
      }
    }
    
    /**
     * Check if a key exists in storage
     * @param {string} key - The key to check
     * @return {boolean} True if the key exists
     */
    static has(key) {
      try {
        return localStorage.getItem(key) !== null;
      } catch (error) {
        console.error('Error checking localStorage:', error);
        return false;
      }
    }
    
    /**
     * Get the size of all stored data
     * @return {number} The size in bytes
     */
    static size() {
      try {
        let totalSize = 0;
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          totalSize += key.length + value.length;
        }
        return totalSize;
      } catch (error) {
        console.error('Error calculating localStorage size:', error);
        return 0;
      }
    }
  }
  
  // =========================================================================
  // USER AUTHENTICATION AND AUTHORIZATION
  // =========================================================================
  
  /**
   * User model
   */
  class User {
    /**
     * Create a new user
     * @param {Object} userData - User data
     */
    constructor(userData = {}) {
      this.id = userData.id || Utils.generateId();
      this.username = userData.username || '';
      this.email = userData.email || '';
      this.firstName = userData.firstName || '';
      this.lastName = userData.lastName || '';
      this.role = userData.role || 'user';
      this.avatar = userData.avatar || '';
      this.createdAt = userData.createdAt || new Date().toISOString();
      this.lastLogin = userData.lastLogin || null;
      this.preferences = userData.preferences || {
        theme: 'light',
        notifications: true,
        language: 'en',
        timezone: 'UTC'
      };
      this.teams = userData.teams || [];
    }
    
    /**
     * Get the user's full name
     * @return {string} The user's full name
     */
    getFullName() {
      return `${this.firstName} ${this.lastName}`.trim() || this.username;
    }
    
    /**
     * Check if the user has a specific role
     * @param {string} role - The role to check
     * @return {boolean} True if the user has the role
     */
    hasRole(role) {
      return this.role === role;
    }
    
    /**
     * Check if the user is an admin
     * @return {boolean} True if the user is an admin
     */
    isAdmin() {
      return this.role === 'admin';
    }
    
    /**
     * Check if the user is in a specific team
     * @param {string} teamId - The team ID to check
     * @return {boolean} True if the user is in the team
     */
    isInTeam(teamId) {
      return this.teams.includes(teamId);
    }
    
    /**
     * Update user data
     * @param {Object} userData - The data to update
     * @return {User} The updated user
     */
    update(userData) {
      Object.assign(this, userData);
      return this;
    }
    
    /**
     * Convert user to a plain object
     * @return {Object} Plain object representation
     */
    toJSON() {
      return {
        id: this.id,
        username: this.username,
        email: this.email,
        firstName: this.firstName,
        lastName: this.lastName,
        role: this.role,
        avatar: this.avatar,
        createdAt: this.createdAt,
        lastLogin: this.lastLogin,
        preferences: this.preferences,
        teams: this.teams
      };
    }
  }
  
  /**
   * Authentication service
   */
  class AuthService {
    constructor() {
      this.currentUser = null;
      this.token = null;
      this.refreshToken = null;
      this.tokenExpiry = null;
      this.apiBaseUrl = 'https://api.taskmanagementsystem.com';
      
      // Try to restore session
      this.restoreSession();
    }
    
    /**
     * Register a new user
     * @param {Object} userData - User registration data
     * @return {Promise<User>} Promise resolving to the new user
     */
    async register(userData) {
      if (!userData.username || !userData.email || !userData.password) {
        throw new Error('Username, email and password are required');
      }
      
      if (!Utils.isValidEmail(userData.email)) {
        throw new Error('Invalid email format');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/auth/register`,
          userData
        );
        
        const user = new User(response.user);
        this.setAuthData(response.token, response.refreshToken, response.expiresIn, user);
        
        EventBus.emit('user:registered', user);
        return user;
      } catch (error) {
        console.error('Registration failed:', error);
        throw error;
      }
    }
    
    /**
     * Log in a user
     * @param {string} email - User email
     * @param {string} password - User password
     * @return {Promise<User>} Promise resolving to the logged in user
     */
    async login(email, password) {
      if (!email || !password) {
        throw new Error('Email and password are required');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/auth/login`,
          { email, password }
        );
        
        const user = new User(response.user);
        this.setAuthData(response.token, response.refreshToken, response.expiresIn, user);
        
        EventBus.emit('user:loggedIn', user);
        return user;
      } catch (error) {
        console.error('Login failed:', error);
        throw error;
      }
    }
    
    /**
     * Log out the current user
     */
    logout() {
      this.currentUser = null;
      this.token = null;
      this.refreshToken = null;
      this.tokenExpiry = null;
      
      Storage.remove('authToken');
      Storage.remove('refreshToken');
      Storage.remove('tokenExpiry');
      Storage.remove('currentUser');
      
      EventBus.emit('user:loggedOut');
    }
    
    /**
     * Refresh the authentication token
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async refreshAuthToken() {
      if (!this.refreshToken) {
        return false;
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/auth/refresh-token`,
          { refreshToken: this.refreshToken }
        );
        
        this.setAuthData(
          response.token,
          response.refreshToken,
          response.expiresIn,
          this.currentUser
        );
        
        return true;
      } catch (error) {
        console.error('Token refresh failed:', error);
        this.logout();
        return false;
      }
    }
    
    /**
     * Check if a user is authenticated
     * @return {boolean} True if a user is authenticated
     */
    isAuthenticated() {
      if (!this.token || !this.tokenExpiry) {
        return false;
      }
      
      // Check if token is expired
      if (new Date() > new Date(this.tokenExpiry)) {
        this.refreshAuthToken();
        return false;
      }
      
      return true;
    }
    
    /**
     * Get the current authenticated user
     * @return {User|null} The current user or null
     */
    getCurrentUser() {
      return this.currentUser;
    }
    
    /**
     * Get the authentication token
     * @return {string|null} The authentication token or null
     */
    getToken() {
      return this.token;
    }
    
    /**
     * Get authentication headers
     * @return {Object} Headers object with authorization
     */
    getAuthHeaders() {
      if (!this.token) {
        return {};
      }
      
      return {
        'Authorization': `Bearer ${this.token}`
      };
    }
    
    /**
     * Update the current user
     * @param {Object} userData - User data to update
     * @return {Promise<User>} Promise resolving to the updated user
     */
    async updateCurrentUser(userData) {
      if (!this.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.put(
          `${this.apiBaseUrl}/users/${this.currentUser.id}`,
          userData,
          this.getAuthHeaders()
        );
        
        this.currentUser.update(response);
        Storage.set('currentUser', this.currentUser.toJSON());
        
        EventBus.emit('user:updated', this.currentUser);
        return this.currentUser;
      } catch (error) {
        console.error('User update failed:', error);
        throw error;
      }
    }
    
    /**
     * Change the user's password
     * @param {string} currentPassword - Current password
     * @param {string} newPassword - New password
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async changePassword(currentPassword, newPassword) {
      if (!this.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        await HttpClient.post(
          `${this.apiBaseUrl}/auth/change-password`,
          { currentPassword, newPassword },
          this.getAuthHeaders()
        );
        
        return true;
      } catch (error) {
        console.error('Password change failed:', error);
        throw error;
      }
    }
    
    /**
     * Request a password reset
     * @param {string} email - User email
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async requestPasswordReset(email) {
      if (!email || !Utils.isValidEmail(email)) {
        throw new Error('Valid email is required');
      }
      
      try {
        await HttpClient.post(
          `${this.apiBaseUrl}/auth/request-reset`,
          { email }
        );
        
        return true;
      } catch (error) {
        console.error('Password reset request failed:', error);
        throw error;
      }
    }
    
    /**
     * Reset the password using a reset token
     * @param {string} resetToken - Password reset token
     * @param {string} newPassword - New password
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async resetPassword(resetToken, newPassword) {
      if (!resetToken || !newPassword) {
        throw new Error('Reset token and new password are required');
      }
      
      try {
        await HttpClient.post(
          `${this.apiBaseUrl}/auth/reset-password`,
          { resetToken, newPassword }
        );
        
        return true;
      } catch (error) {
        console.error('Password reset failed:', error);
        throw error;
      }
    }
    
    /**
     * Set authentication data
     * @param {string} token - Auth token
     * @param {string} refreshToken - Refresh token
     * @param {number} expiresIn - Token expiry in seconds
     * @param {User} user - User object
     */
    setAuthData(token, refreshToken, expiresIn, user) {
      this.token = token;
      this.refreshToken = refreshToken;
      this.currentUser = user;
      
      // Calculate expiry date
      const expiryDate = new Date();
      expiryDate.setSeconds(expiryDate.getSeconds() + expiresIn);
      this.tokenExpiry = expiryDate.toISOString();
      
      // Save to storage
      Storage.set('authToken', token);
      Storage.set('refreshToken', refreshToken);
      Storage.set('tokenExpiry', this.tokenExpiry);
      Storage.set('currentUser', user.toJSON());
    }
    
    /**
     * Restore user session from storage
     */
    restoreSession() {
      const token = Storage.get('authToken');
      const refreshToken = Storage.get('refreshToken');
      const tokenExpiry = Storage.get('tokenExpiry');
      const userData = Storage.get('currentUser');
      
      if (token && refreshToken && tokenExpiry && userData) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiry = tokenExpiry;
        this.currentUser = new User(userData);
        
        // Check if token is expired and refresh if needed
        if (new Date() > new Date(this.tokenExpiry)) {
          this.refreshAuthToken();
        }
      }
    }
  }
  
  /**
   * Permission checker
   */
  class PermissionChecker {
    /**
     * Check if a user has a specific permission
     * @param {User} user - The user to check
     * @param {string} permission - The permission to check
     * @param {Object} resource - The resource to check permission for
     * @return {boolean} True if the user has the permission
     */
    static hasPermission(user, permission, resource = null) {
      if (!user) return false;
      
      // Admin always has all permissions
      if (user.isAdmin()) return true;
      
      switch (permission) {
        case 'create:task':
          return true; // All users can create tasks
          
        case 'edit:task':
          return resource && (
            resource.userId === user.id ||
            resource.assignees.includes(user.id) ||
            user.hasRole('manager')
          );
          
        case 'delete:task':
          return resource && (
            resource.userId === user.id ||
            user.hasRole('manager')
          );
          
        case 'create:project':
          return user.hasRole('manager');
          
        case 'edit:project':
          return resource && (
            resource.ownerId === user.id ||
            user.hasRole('manager')
          );
          
        case 'delete:project':
          return resource && (
            resource.ownerId === user.id ||
            user.hasRole('manager')
          );
          
        case 'manage:users':
          return user.hasRole('manager');
          
        case 'create:team':
          return user.hasRole('manager');
          
        default:
          return false;
      }
    }
  }
  
  // =========================================================================
  // TASK MANAGEMENT
  // =========================================================================
  
  /**
   * Task model
   */
  class Task {
    /**
     * Create a new task
     * @param {Object} taskData - Task data
     */
    constructor(taskData = {}) {
      this.id = taskData.id || Utils.generateId();
      this.title = taskData.title || '';
      this.description = taskData.description || '';
      this.status = taskData.status || 'todo';
      this.priority = taskData.priority || 'medium';
      this.dueDate = taskData.dueDate || null;
      this.createdAt = taskData.createdAt || new Date().toISOString();
      this.updatedAt = taskData.updatedAt || new Date().toISOString();
      this.userId = taskData.userId || null;
      this.projectId = taskData.projectId || null;
      this.assignees = taskData.assignees || [];
      this.tags = taskData.tags || [];
      this.attachments = taskData.attachments || [];
      this.comments = taskData.comments || [];
      this.completedAt = taskData.completedAt || null;
      this.estimatedTime = taskData.estimatedTime || null;
      this.actualTime = taskData.actualTime || 0;
      this.dependencies = taskData.dependencies || [];
    }
    
    /**
     * Check if the task is complete
     * @return {boolean} True if the task is complete
     */
    isComplete() {
      return this.status === 'completed';
    }
    
    /**
     * Check if the task is overdue
     * @return {boolean} True if the task is overdue
     */
    isOverdue() {
      if (!this.dueDate || this.isComplete()) {
        return false;
      }
      
      return Utils.isDatePast(this.dueDate);
    }
    
    /**
     * Get the days until the task is due
     * @return {number|null} Days until due or null if no due date
     */
    daysUntilDue() {
      if (!this.dueDate) {
        return null;
      }
      
      const now = new Date();
      const due = new Date(this.dueDate);
      const diff = due - now;
      return Math.ceil(diff / (1000 * 60 * 60 * 24));
    }
    
    /**
     * Mark the task as complete
     */
    complete() {
      this.status = 'completed';
      this.completedAt = new Date().toISOString();
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Add a comment to the task
     * @param {string} userId - User ID
     * @param {string} content - Comment content
     * @return {Object} The new comment
     */
    addComment(userId, content) {
      const comment = {
        id: Utils.generateId(),
        userId: userId,
        content: content,
        createdAt: new Date().toISOString()
      };
      
      this.comments.push(comment);
      this.updatedAt = new Date().toISOString();
      
      return comment;
    }
    
    /**
     * Add an attachment to the task
     * @param {Object} attachment - Attachment data
     * @return {Object} The new attachment
     */
    addAttachment(attachment) {
      const newAttachment = {
        id: Utils.generateId(),
        name: attachment.name,
        url: attachment.url,
        size: attachment.size,
        type: attachment.type,
        uploadedAt: new Date().toISOString(),
        uploadedBy: attachment.uploadedBy
      };
      
      this.attachments.push(newAttachment);
      this.updatedAt = new Date().toISOString();
      
      return newAttachment;
    }
    
    /**
     * Add a tag to the task
     * @param {string} tag - Tag to add
     */
    addTag(tag) {
      if (!this.tags.includes(tag)) {
        this.tags.push(tag);
        this.updatedAt = new Date().toISOString();
      }
    }
    
    /**
     * Remove a tag from the task
     * @param {string} tag - Tag to remove
     */
    removeTag(tag) {
      this.tags = this.tags.filter(t => t !== tag);
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Assign a user to the task
     * @param {string} userId - User ID to assign
     */
    assignUser(userId) {
      if (!this.assignees.includes(userId)) {
        this.assignees.push(userId);
        this.updatedAt = new Date().toISOString();
      }
    }
    
    /**
     * Unassign a user from the task
     * @param {string} userId - User ID to unassign
     */
    unassignUser(userId) {
      this.assignees = this.assignees.filter(id => id !== userId);
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Add a dependency to the task
     * @param {string} taskId - Task ID to add as dependency
     */
    addDependency(taskId) {
      if (!this.dependencies.includes(taskId)) {
        this.dependencies.push(taskId);
        this.updatedAt = new Date().toISOString();
      }
    }
    
    /**
     * Remove a dependency from the task
     * @param {string} taskId - Task ID to remove from dependencies
     */
    removeDependency(taskId) {
      this.dependencies = this.dependencies.filter(id => id !== taskId);
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Log time spent on the task
     * @param {number} hours - Hours spent
     */
    logTime(hours) {
      this.actualTime += hours;
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Update the task status
     * @param {string} status - New status
     */
    updateStatus(status) {
      this.status = status;
      
      if (status === 'completed' && !this.completedAt) {
        this.completedAt = new Date().toISOString();
      } else if (status !== 'completed') {
        this.completedAt = null;
      }
      
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Convert task to a plain object
     * @return {Object} Plain object representation
     */
    toJSON() {
      return {
        id: this.id,
        title: this.title,
        description: this.description,
        status: this.status,
        priority: this.priority,
        dueDate: this.dueDate,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
        userId: this.userId,
        projectId: this.projectId,
        assignees: this.assignees,
        tags: this.tags,
        attachments: this.attachments,
        comments: this.comments,
        completedAt: this.completedAt,
        estimatedTime: this.estimatedTime,
        actualTime: this.actualTime,
        dependencies: this.dependencies
      };
    }
  }
  
  /**
   * Task service
   */
  class TaskService {
    constructor(authService) {
      this.authService = authService;
      this.apiBaseUrl = 'https://api.taskmanagementsystem.com';
    }
    
    /**
     * Get all tasks
     * @param {Object} filters - Optional filters
     * @return {Promise<Array<Task>>} Promise resolving to tasks array
     */
    async getTasks(filters = {}) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        // Build query string from filters
        const queryParams = new URLSearchParams();
        for (const [key, value] of Object.entries(filters)) {
          if (value !== undefined && value !== null) {
            queryParams.append(key, value);
          }
        }
        
        const queryString = queryParams.toString();
        const url = `${this.apiBaseUrl}/tasks${queryString ? `?${queryString}` : ''}`;
        
        const response = await HttpClient.get(
          url,
          this.authService.getAuthHeaders()
        );
        
        return response.map(taskData => new Task(taskData));
      } catch (error) {
        console.error('Failed to fetch tasks:', error);
        throw error;
      }
    }
    
    /**
     * Get a task by ID
     * @param {string} taskId - Task ID
     * @return {Promise<Task>} Promise resolving to the task
     */
    async getTask(taskId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.get(
          `${this.apiBaseUrl}/tasks/${taskId}`,
          this.authService.getAuthHeaders()
        );
        
        return new Task(response);
      } catch (error) {
        console.error(`Failed to fetch task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Create a new task
     * @param {Object} taskData - Task data
     * @return {Promise<Task>} Promise resolving to the new task
     */
    async createTask(taskData) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      if (!taskData.title) {
        throw new Error('Task title is required');
      }
      
      try {
        // Set current user as creator if not specified
        if (!taskData.userId) {
          taskData.userId = this.authService.getCurrentUser().id;
        }
        
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/tasks`,
          taskData,
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:created', task);
        
        return task;
      } catch (error) {
        console.error('Failed to create task:', error);
        throw error;
      }
    }
    
    /**
     * Update a task
     * @param {string} taskId - Task ID
     * @param {Object} taskData - Task data to update
     * @return {Promise<Task>} Promise resolving to the updated task
     */
    async updateTask(taskId, taskData) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.put(
          `${this.apiBaseUrl}/tasks/${taskId}`,
          taskData,
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:updated', task);
        
        return task;
      } catch (error) {
        console.error(`Failed to update task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Delete a task
     * @param {string} taskId - Task ID
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async deleteTask(taskId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        await HttpClient.delete(
          `${this.apiBaseUrl}/tasks/${taskId}`,
          this.authService.getAuthHeaders()
        );
        
        EventBus.emit('task:deleted', taskId);
        return true;
      } catch (error) {
        console.error(`Failed to delete task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Add a comment to a task
     * @param {string} taskId - Task ID
     * @param {string} content - Comment content
     * @return {Promise<Object>} Promise resolving to the new comment
     */
    async addComment(taskId, content) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      if (!content) {
        throw new Error('Comment content is required');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/tasks/${taskId}/comments`,
          {
            userId: this.authService.getCurrentUser().id,
            content: content
          },
          this.authService.getAuthHeaders()
        );
        
        EventBus.emit('task:commentAdded', { taskId, comment: response });
        return response;
      } catch (error) {
        console.error(`Failed to add comment to task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Add an attachment to a task
     * @param {string} taskId - Task ID
     * @param {File} file - File to upload
     * @return {Promise<Object>} Promise resolving to the attachment
     */
    async addAttachment(taskId, file) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      if (!file) {
        throw new Error('File is required');
      }
      
      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('uploadedBy', this.authService.getCurrentUser().id);
        
        const response = await fetch(
          `${this.apiBaseUrl}/tasks/${taskId}/attachments`,
          {
            method: 'POST',
            headers: {
              ...this.authService.getAuthHeaders()
              // FormData sets its own Content-Type
            },
            body: formData
          }
        );
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const attachment = await response.json();
        EventBus.emit('task:attachmentAdded', { taskId, attachment });
        
        return attachment;
      } catch (error) {
        console.error(`Failed to add attachment to task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Assign a user to a task
     * @param {string} taskId - Task ID
     * @param {string} userId - User ID
     * @return {Promise<Task>} Promise resolving to the updated task
     */
    async assignUser(taskId, userId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/tasks/${taskId}/assignees`,
          { userId },
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:userAssigned', { taskId, userId });
        
        return task;
      } catch (error) {
        console.error(`Failed to assign user to task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Unassign a user from a task
     * @param {string} taskId - Task ID
     * @param {string} userId - User ID
     * @return {Promise<Task>} Promise resolving to the updated task
     */
    async unassignUser(taskId, userId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.delete(
          `${this.apiBaseUrl}/tasks/${taskId}/assignees/${userId}`,
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:userUnassigned', { taskId, userId });
        
        return task;
      } catch (error) {
        console.error(`Failed to unassign user from task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Update task status
     * @param {string} taskId - Task ID
     * @param {string} status - New status
     * @return {Promise<Task>} Promise resolving to the updated task
     */
    async updateStatus(taskId, status) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.put(
          `${this.apiBaseUrl}/tasks/${taskId}/status`,
          { status },
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:statusUpdated', { taskId, status });
        
        return task;
      } catch (error) {
        console.error(`Failed to update task status ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Log time spent on a task
     * @param {string} taskId - Task ID
     * @param {number} hours - Hours spent
     * @return {Promise<Task>} Promise resolving to the updated task
     */
    async logTime(taskId, hours) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      if (hours <= 0) {
        throw new Error('Hours must be greater than zero');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/tasks/${taskId}/time-logs`,
          { hours },
          this.authService.getAuthHeaders()
        );
        
        const task = new Task(response);
        EventBus.emit('task:timeLogged', { taskId, hours });
        
        return task;
      } catch (error) {
        console.error(`Failed to log time for task ${taskId}:`, error);
        throw error;
      }
    }
    
    /**
     * Search tasks
     * @param {string} query - Search query
     * @return {Promise<Array<Task>>} Promise resolving to tasks array
     */
    async searchTasks(query) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.get(
          `${this.apiBaseUrl}/tasks/search?q=${encodeURIComponent(query)}`,
          this.authService.getAuthHeaders()
        );
        
        return response.map(taskData => new Task(taskData));
      } catch (error) {
        console.error(`Search tasks failed for "${query}":`, error);
        throw error;
      }
    }
  }
  
  // =========================================================================
  // PROJECT MANAGEMENT
  // =========================================================================
  
  /**
   * Project model
   */
  class Project {
    /**
     * Create a new project
     * @param {Object} projectData - Project data
     */
    constructor(projectData = {}) {
      this.id = projectData.id || Utils.generateId();
      this.name = projectData.name || '';
      this.description = projectData.description || '';
      this.ownerId = projectData.ownerId || null;
      this.teamId = projectData.teamId || null;
      this.status = projectData.status || 'active';
      this.startDate = projectData.startDate || new Date().toISOString();
      this.endDate = projectData.endDate || null;
      this.createdAt = projectData.createdAt || new Date().toISOString();
      this.updatedAt = projectData.updatedAt || new Date().toISOString();
      this.tasks = projectData.tasks || [];
      this.members = projectData.members || [];
      this.tags = projectData.tags || [];
      this.color = projectData.color || '#3498db';
      this.icon = projectData.icon || 'folder';
      this.completedAt = projectData.completedAt || null;
      this.progress = projectData.progress || 0;
    }
    
    /**
     * Check if the project is complete
     * @return {boolean} True if the project is complete
     */
    isComplete() {
      return this.status === 'completed';
    }
    
    /**
     * Add a member to the project
     * @param {string} userId - User ID to add
     */
    addMember(userId) {
      if (!this.members.includes(userId)) {
        this.members.push(userId);
        this.updatedAt = new Date().toISOString();
      }
    }
    
    /**
     * Remove a member from the project
     * @param {string} userId - User ID to remove
     */
    removeMember(userId) {
      this.members = this.members.filter(id => id !== userId);
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Add a task to the project
     * @param {string} taskId - Task ID to add
     */
    addTask(taskId) {
      if (!this.tasks.includes(taskId)) {
        this.tasks.push(taskId);
        this.updatedAt = new Date().toISOString();
        this.updateProgress();
      }
    }
    
    /**
     * Remove a task from the project
     * @param {string} taskId - Task ID to remove
     */
    removeTask(taskId) {
      this.tasks = this.tasks.filter(id => id !== taskId);
      this.updatedAt = new Date().toISOString();
      this.updateProgress();
    }
    
    /**
     * Add a tag to the project
     * @param {string} tag - Tag to add
     */
    addTag(tag) {
      if (!this.tags.includes(tag)) {
        this.tags.push(tag);
        this.updatedAt = new Date().toISOString();
      }
    }
    
    /**
     * Remove a tag from the project
     * @param {string} tag - Tag to remove
     */
    removeTag(tag) {
      this.tags = this.tags.filter(t => t !== tag);
      this.updatedAt = new Date().toISOString();
    }
    
    /**
     * Update project progress
     * @param {number} progress - Progress percentage (0-100)
     */
    updateProgress(progress = null) {
      if (progress !== null) {
        this.progress = Math.min(100, Math.max(0, progress));
      }
      
      this.updatedAt = new Date().toISOString();
      
      // Auto mark as completed if progress is 100%
      if (this.progress === 100 && this.status !== 'completed') {
        this.status = 'completed';
        this.completedAt = new Date().toISOString();
      } else if (this.progress < 100 && this.status === 'completed') {
        this.status = 'active';
        this.completedAt = null;
      }
    }
    
    /**
     * Get days until project end
     * @return {number|null} Days until end or null if no end date
     */
    daysUntilEnd() {
      if (!this.endDate) {
        return null;
      }
      
      return Utils.daysBetween(new Date(), new Date(this.endDate));
    }
    
    /**
     * Check if the project is overdue
     * @return {boolean} True if the project is overdue
     */
    isOverdue() {
      if (!this.endDate || this.isComplete()) {
        return false;
      }
      
      return Utils.isDatePast(this.endDate);
    }
    
    /**
     * Convert project to a plain object
     * @return {Object} Plain object representation
     */
    toJSON() {
      return {
        id: this.id,
        name: this.name,
        description: this.description,
        ownerId: this.ownerId,
        teamId: this.teamId,
        status: this.status,
        startDate: this.startDate,
        endDate: this.endDate,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
        tasks: this.tasks,
        members: this.members,
        tags: this.tags,
        color: this.color,
        icon: this.icon,
        completedAt: this.completedAt,
        progress: this.progress
      };
    }
  }
  
  /**
   * Project service
   */
  class ProjectService {
    constructor(authService) {
      this.authService = authService;
      this.apiBaseUrl = 'https://api.taskmanagementsystem.com';
    }
    
    /**
     * Get all projects
     * @param {Object} filters - Optional filters
     * @return {Promise<Array<Project>>} Promise resolving to projects array
     */
    async getProjects(filters = {}) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        // Build query string from filters
        const queryParams = new URLSearchParams();
        for (const [key, value] of Object.entries(filters)) {
          if (value !== undefined && value !== null) {
            queryParams.append(key, value);
          }
        }
        
        const queryString = queryParams.toString();
        const url = `${this.apiBaseUrl}/projects${queryString ? `?${queryString}` : ''}`;
        
        const response = await HttpClient.get(
          url,
          this.authService.getAuthHeaders()
        );
        
        return response.map(projectData => new Project(projectData));
      } catch (error) {
        console.error('Failed to fetch projects:', error);
        throw error;
      }
    }
    
    /**
     * Get a project by ID
     * @param {string} projectId - Project ID
     * @return {Promise<Project>} Promise resolving to the project
     */
    async getProject(projectId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.get(
          `${this.apiBaseUrl}/projects/${projectId}`,
          this.authService.getAuthHeaders()
        );
        
        return new Project(response);
      } catch (error) {
        console.error(`Failed to fetch project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Create a new project
     * @param {Object} projectData - Project data
     * @return {Promise<Project>} Promise resolving to the new project
     */
    async createProject(projectData) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      if (!projectData.name) {
        throw new Error('Project name is required');
      }
      
      try {
        // Set current user as owner if not specified
        if (!projectData.ownerId) {
          projectData.ownerId = this.authService.getCurrentUser().id;
        }
        
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/projects`,
          projectData,
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:created', project);
        
        return project;
      } catch (error) {
        console.error('Failed to create project:', error);
        throw error;
      }
    }
    
    /**
     * Update a project
     * @param {string} projectId - Project ID
     * @param {Object} projectData - Project data to update
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async updateProject(projectId, projectData) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.put(
          `${this.apiBaseUrl}/projects/${projectId}`,
          projectData,
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:updated', project);
        
        return project;
      } catch (error) {
        console.error(`Failed to update project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Delete a project
     * @param {string} projectId - Project ID
     * @return {Promise<boolean>} Promise resolving to success status
     */
    async deleteProject(projectId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        await HttpClient.delete(
          `${this.apiBaseUrl}/projects/${projectId}`,
          this.authService.getAuthHeaders()
        );
        
        EventBus.emit('project:deleted', projectId);
        return true;
      } catch (error) {
        console.error(`Failed to delete project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Add a member to a project
     * @param {string} projectId - Project ID
     * @param {string} userId - User ID
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async addMember(projectId, userId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/projects/${projectId}/members`,
          { userId },
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:memberAdded', { projectId, userId });
        
        return project;
      } catch (error) {
        console.error(`Failed to add member to project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Remove a member from a project
     * @param {string} projectId - Project ID
     * @param {string} userId - User ID
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async removeMember(projectId, userId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.delete(
          `${this.apiBaseUrl}/projects/${projectId}/members/${userId}`,
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:memberRemoved', { projectId, userId });
        
        return project;
      } catch (error) {
        console.error(`Failed to remove member from project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Add a task to a project
     * @param {string} projectId - Project ID
     * @param {string} taskId - Task ID
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async addTask(projectId, taskId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.post(
          `${this.apiBaseUrl}/projects/${projectId}/tasks`,
          { taskId },
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:taskAdded', { projectId, taskId });
        
        return project;
      } catch (error) {
        console.error(`Failed to add task to project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Remove a task from a project
     * @param {string} projectId - Project ID
     * @param {string} taskId - Task ID
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async removeTask(projectId, taskId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.delete(
          `${this.apiBaseUrl}/projects/${projectId}/tasks/${taskId}`,
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:taskRemoved', { projectId, taskId });
        
        return project;
      } catch (error) {
        console.error(`Failed to remove task from project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Get project tasks
     * @param {string} projectId - Project ID
     * @return {Promise<Array<Task>>} Promise resolving to tasks array
     */
    async getProjectTasks(projectId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.get(
          `${this.apiBaseUrl}/projects/${projectId}/tasks`,
          this.authService.getAuthHeaders()
        );
        
        return response.map(taskData => new Task(taskData));
      } catch (error) {
        console.error(`Failed to fetch tasks for project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Update project progress
     * @param {string} projectId - Project ID
     * @param {number} progress - Progress percentage
     * @return {Promise<Project>} Promise resolving to the updated project
     */
    async updateProgress(projectId, progress) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        const response = await HttpClient.put(
          `${this.apiBaseUrl}/projects/${projectId}/progress`,
          { progress },
          this.authService.getAuthHeaders()
        );
        
        const project = new Project(response);
        EventBus.emit('project:progressUpdated', { projectId, progress });
        
        return project;
      } catch (error) {
        console.error(`Failed to update progress for project ${projectId}:`, error);
        throw error;
      }
    }
    
    /**
     * Get project statistics
     * @param {string} projectId - Project ID
     * @return {Promise<Object>} Promise resolving to project statistics
     */
    async getProjectStats(projectId) {
      if (!this.authService.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      try {
        return await HttpClient.get(
          `${this.apiBaseUrl}/projects/${projectId}/stats`,
          this.authService.getAuthHeaders()
        );
      } catch (error) {
        console.error(`Failed to fetch stats for project ${projectId}:`, error);
        throw error;
      }
    }
  }
  
  // =========================================================================
  // TEAM COLLABORATION
  // =========================================================================
  
  /**
   * Team model
   */
  class Team {
    /**
     * Create a new team
     * @param {Object} teamData - Team data
     */
    constructor(teamData = {}) {
      this.id = teamData.id || Utils.generateId();