import { API_BASE } from '$lib/api';
import { toast } from '$lib/stores/toast';

let csrfToken: string | null = null;
let tokenRefreshPromise: Promise<string> | null = null;

/**
 * Fetch the CSRF token from the server with enhanced error handling
 */
async function fetchCSRFToken(): Promise<string> {
    try {
        const response = await fetch(`${API_BASE}/api/csrf-token`, {
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Unknown error');
            throw new Error(`CSRF token fetch failed (${response.status}): ${errorText}`);
        }

        const data = await response.json();
        if (!data.csrf_token) {
            throw new Error('CSRF token not found in server response');
        }

        csrfToken = data.csrf_token;
        return csrfToken as string;
    } catch (error) {
        // Show user-friendly error message
        const message = error instanceof Error ? error.message : 'Failed to fetch security token';
        toast.error(`Security Error: ${message}`, 8000);
        throw error;
    }
}

/**
 * Get CSRF token from memory or fetch it if not available
 * Prevents concurrent token fetches using a promise cache
 */
export async function getCSRFToken(): Promise<string> {
    if (csrfToken) {
        return csrfToken;
    }

    // If a token refresh is already in progress, wait for it
    if (tokenRefreshPromise) {
        return tokenRefreshPromise;
    }

    // Start a new token refresh
    tokenRefreshPromise = fetchCSRFToken();
    
    try {
        const token = await tokenRefreshPromise;
        return token;
    } finally {
        // Clear the promise cache after completion (success or failure)
        tokenRefreshPromise = null;
    }
}

/**
 * Enhanced fetch function that automatically includes CSRF tokens for unsafe methods
 */
export async function csrfFetch(url: string, options: RequestInit = {}): Promise<Response> {
    const method = options.method?.toUpperCase() || 'GET';
    
    // For safe methods, just use regular fetch
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
        return fetch(url, {
            ...options,
            credentials: 'include'
        });
    }

    // For unsafe methods, get CSRF token and include it
    try {
        const token = await getCSRFToken();
        
        const headers = new Headers(options.headers);
        headers.set('X-CSRF-Token', token);
        
        return fetch(url, {
            ...options,
            headers,
            credentials: 'include'
        });
    } catch (error) {
        // SECURITY: Never proceed without CSRF token for unsafe methods
        // This prevents CSRF attacks and ensures proper error handling
        const message = error instanceof Error ? error.message : 'CSRF token unavailable';
        toast.error(`Request blocked: ${message}`, 8000);
        
        // Return a failed response rather than attempting the request without CSRF token
        return new Response(JSON.stringify({ 
            error: 'CSRF token required but unavailable',
            details: message 
        }), {
            status: 403,
            statusText: 'CSRF Token Required',
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * Clear cached CSRF token (useful when it becomes invalid)
 */
export function clearCSRFToken(): void {
    csrfToken = null;
    // Also clear any ongoing refresh promise
    tokenRefreshPromise = null;
}

/**
 * Retry a request with a fresh CSRF token if it fails with 403
 * Enhanced with better error detection and user feedback
 */
export async function csrfFetchWithRetry(url: string, options: RequestInit = {}, maxRetries: number = 2): Promise<Response> {
    let lastError: Error | null = null;
    let response: Response;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            response = await csrfFetch(url, options);
            
            // Check if this is a CSRF-related error
            if (response.status === 403) {
                const responseText = await response.text();
                const isCSRFError = responseText.includes('CSRF') || 
                                  responseText.includes('csrf') || 
                                  responseText.includes('token');
                
                if (isCSRFError && attempt < maxRetries) {
                    // Show user feedback for token refresh
                    toast.info('Refreshing security token...', 3000);
                    
                    // Clear token and retry
                    clearCSRFToken();
                    continue;
                } else {
                    // Create new response with the text we already read
                    return new Response(responseText, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers
                    });
                }
            }
            
            // Success or non-CSRF error
            return response;
            
        } catch (error) {
            lastError = error instanceof Error ? error : new Error('Unknown error');
            
            if (attempt < maxRetries) {
                toast.warning(`Request failed, retrying... (${attempt}/${maxRetries})`, 3000);
                clearCSRFToken();
                
                // Exponential backoff
                await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt - 1) * 1000));
                continue;
            }
        }
    }
    
    // All retries failed
    const errorMessage = lastError?.message || 'Request failed after multiple attempts';
    toast.error(`Request failed: ${errorMessage}`, 8000);
    
    // Return a meaningful error response
    return new Response(JSON.stringify({ 
        error: 'Request failed after retries',
        details: errorMessage,
        attempts: maxRetries
    }), {
        status: 500,
        statusText: 'Request Failed',
        headers: { 'Content-Type': 'application/json' }
    });
}

/**
 * Check if a response indicates a CSRF error
 */
export function isCSRFError(response: Response, responseText?: string): boolean {
    if (response.status !== 403) return false;
    
    // Check headers for CSRF indicators
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return true; // Likely our structured CSRF error
    }
    
    // Check response text if provided
    if (responseText) {
        return responseText.includes('CSRF') || 
               responseText.includes('csrf') || 
               responseText.includes('token') ||
               responseText.includes('forbidden');
    }
    
    return false;
}

/**
 * Handle CSRF errors with user-friendly messages
 */
export function handleCSRFError(error: any, context: string = 'request'): void {
    let message = `Security verification failed during ${context}`;
    
    if (error instanceof Error) {
        if (error.message.includes('CSRF')) {
            message = `Security token expired during ${context}. Please try again.`;
        } else if (error.message.includes('403')) {
            message = `Access denied during ${context}. Please refresh and try again.`;
        } else {
            message = `${context} failed: ${error.message}`;
        }
    }
    
    toast.error(message, 8000);
}

/**
 * Preload CSRF token for faster subsequent requests
 */
export async function preloadCSRFToken(): Promise<void> {
    try {
        await getCSRFToken();
        console.log('CSRF token preloaded successfully');
    } catch (error) {
        console.warn('Failed to preload CSRF token:', error);
        // Don't show toast for preload failures as they're not user-initiated
    }
}