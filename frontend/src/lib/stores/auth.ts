import {writable} from 'svelte/store';
import {browser} from '$app/environment';
import {API_BASE} from '$lib/api';
import {csrfFetchWithRetry, handleCSRFError, preloadCSRFToken} from '$lib/csrf';

interface User {
    user_id: string;
    username: string;
    email: string;
    roles: string[];
}

interface AuthState {
    user: User | null;
    loading: boolean;
    error: string | null;
}

const initialState: AuthState = {
    user: null,
    loading: false,
    error: null
};

export const auth = writable<AuthState>(initialState);

class AuthService {
    async login(emailOrUsername: string, password: string) {
        auth.update(state => ({...state, loading: true, error: null}));

        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email_or_username: emailOrUsername,
                    password
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Login failed');
            }

            await this.getCurrentUser();
            return true;
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'login');
            }
            
            auth.update(state => ({
                ...state,
                loading: false,
                error: error instanceof Error ? error.message : 'Login failed'
            }));
            return false;
        }
    }

    async register(email: string, username: string, password: string) {
        auth.update(state => ({...state, loading: true, error: null}));

        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email,
                    username,
                    password
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Registration failed');
            }

            const data = await response.json();

            if (data.tokens) {
                await this.getCurrentUser();
            } else {
                auth.update(state => ({
                    ...state,
                    loading: false,
                    error: null
                }));
            }

            return data;
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'registration');
            }
            
            auth.update(state => ({
                ...state,
                loading: false,
                error: error instanceof Error ? error.message : 'Registration failed'
            }));
            throw error;
        }
    }

    async logout() {
        try {
            await csrfFetchWithRetry(`${API_BASE}/api/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({refresh_token: ''})
            });
        } catch (error) {
            console.error('Logout error:', error);
            // Don't show CSRF errors for logout as it's not critical
            // The client-side state will be cleared regardless
        } finally {
            auth.set({user: null, loading: false, error: null});
        }
    }

    async getCurrentUser() {
        if (!browser) return;

        try {
            const response = await fetch(`${API_BASE}/api/auth/me`, {
                credentials: 'include'
            });

            if (response.ok) {
                const user = await response.json();
                auth.update(state => ({
                    ...state,
                    user,
                    loading: false,
                    error: null
                }));
            } else {
                auth.set({user: null, loading: false, error: null});
            }
        } catch (error) {
            auth.set({user: null, loading: false, error: null});
        }
    }

    async changePassword(oldPassword: string, newPassword: string) {
        auth.update(state => ({...state, loading: true, error: null}));

        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/change-password`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    old_password: oldPassword,
                    new_password: newPassword
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to change password');
            }

            auth.update(state => ({...state, loading: false, error: null}));
            return await response.json();
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'password change');
            }
            
            auth.update(state => ({
                ...state,
                loading: false,
                error: error instanceof Error ? error.message : 'Failed to change password'
            }));
            throw error;
        }
    }

    async forgotPassword(email: string) {
        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/forgot-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({email})
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to send reset email');
            }

            return await response.json();
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'password reset request');
            }
            throw error;
        }
    }

    async resetPassword(token: string, password: string) {
        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({token, password})
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to reset password');
            }

            return await response.json();
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'password reset');
            }
            throw error;
        }
    }

    async verifyEmail(token: string) {
        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/verify-email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({token})
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Email verification failed');
            }

            return await response.json();
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'email verification');
            }
            throw error;
        }
    }

    async deleteAccount(password: string) {
        auth.update(state => ({...state, loading: true, error: null}));

        try {
            const response = await csrfFetchWithRetry(`${API_BASE}/api/auth/delete-account`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({password})
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to delete account');
            }

            auth.set({user: null, loading: false, error: null});
            return await response.json();
        } catch (error) {
            // Handle CSRF-specific errors with better user messaging
            if (error instanceof Error && error.message.includes('CSRF')) {
                handleCSRFError(error, 'account deletion');
            }
            
            auth.update(state => ({
                ...state,
                loading: false,
                error: error instanceof Error ? error.message : 'Failed to delete account'
            }));
            throw error;
        }
    }

    clearError() {
        auth.update(state => ({...state, error: null}));
    }
}

export const authService = new AuthService();

if (browser) {
    // Initialize auth and preload CSRF token
    authService.getCurrentUser();
    preloadCSRFToken();
}